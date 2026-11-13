// Command bench compares tunnel engines on a controlled OpenVPN server: it
// opens N tunnels at once, sends real traffic through each, samples the
// engine's resources, then stops every tunnel. CI only (root, TUN).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

type sessionReport struct {
	Device    string  `json:"device"`
	ConnectMs float64 `json:"connect_ms"`
	TrafficMs float64 `json:"traffic_ms"`
	StopMs    float64 `json:"stop_ms"`
	Error     string  `json:"error,omitempty"`
}

// report covers only the engine: for core that is this whole process, so the
// Go controller is included and BaselineRSSKB shows its share before any
// tunnel; for cli it is the sum over the openvpn child processes.
type report struct {
	Engine          string          `json:"engine"`
	Version         string          `json:"version"`
	Tunnels         int             `json:"tunnels"`
	Connected       int             `json:"connected"`
	TrafficOK       int             `json:"traffic_ok"`
	Stopped         int             `json:"stopped"`
	WallReadyMs     float64         `json:"wall_ready_ms"`
	MedianConnectMs float64         `json:"median_connect_ms"`
	MaxConnectMs    float64         `json:"max_connect_ms"`
	MaxStopMs       float64         `json:"max_stop_ms"`
	Processes       int             `json:"processes"`
	Threads         int             `json:"threads"`
	RSSKB           int             `json:"rss_kb"`
	PSSKB           int             `json:"pss_kb"`
	PeakRSSKB       int             `json:"peak_rss_kb"`
	BaselineRSSKB   int             `json:"baseline_rss_kb"`
	CPUMs           float64         `json:"cpu_ms"`
	Sessions        []sessionReport `json:"sessions"`
	Errors          []string        `json:"errors,omitempty"`
}

func main() {
	engineName := flag.String("engine", "core", "core (embedded OpenVPN 3 Core) or cli (one openvpn process per tunnel)")
	pattern := flag.String("profiles", "", "glob of client profiles, one tunnel each (at most 128)")
	target := flag.String("target", "", "URL fetched through every tunnel; must answer vpn-client=<VPN address>")
	reportPath := flag.String("report", "", "JSON report path")
	connectTimeout := flag.Duration("connect-timeout", 60*time.Second, "per-tunnel connect timeout")
	stopTimeout := flag.Duration("stop-timeout", 15*time.Second, "per-tunnel stop timeout")
	flag.Parse()
	if *pattern == "" || *target == "" || *reportPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	var selected engine
	switch *engineName {
	case "core":
		selected = coreEngine{timeout: *connectTimeout}
	case "cli":
		selected = cliEngine{timeout: *connectTimeout, workDir: os.TempDir()}
	default:
		log.Fatalf("unknown engine %q", *engineName)
	}
	result, runErr := run(selected, *pattern, *target, *connectTimeout, *stopTimeout)
	if runErr != nil {
		result.Errors = append(result.Errors, runErr.Error())
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*reportPath, append(encoded, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s x%d: connected %d, traffic %d, stopped %d, ready %.0f ms, rss %d KiB, errors %d\n",
		result.Engine, result.Tunnels, result.Connected, result.TrafficOK, result.Stopped,
		result.WallReadyMs, result.RSSKB, len(result.Errors))
	if len(result.Errors) > 0 {
		os.Exit(1)
	}
}

func run(selected engine, pattern, target string, connectTimeout, stopTimeout time.Duration) (report, error) {
	result := report{Engine: selected.Name(), Version: selected.Version()}
	profiles, err := nodes.LoadProfiles(pattern)
	if err != nil {
		return result, err
	}
	if len(profiles) > 128 {
		return result, fmt.Errorf("%d profiles exceed the 128-tunnel limit", len(profiles))
	}
	result.Tunnels = len(profiles)
	result.Sessions = make([]sessionReport, len(profiles))
	baseline, err := readProc("self")
	if err != nil {
		return result, err
	}
	result.BaselineRSSKB = baseline.rssKB

	tunnels := make([]tunnel, len(profiles))
	started := time.Now()
	parallel(len(profiles), func(i int) {
		session := &result.Sessions[i]
		session.Device = fmt.Sprintf("tun%d", i)
		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		begin := time.Now()
		t, err := selected.Connect(ctx, profiles[i].Profile, session.Device)
		session.ConnectMs = milliseconds(begin)
		if err != nil {
			session.Error = "connect: " + err.Error()
			return
		}
		tunnels[i] = t
	})
	result.WallReadyMs = milliseconds(started)

	var routeCleanups []func() error
	for i, t := range tunnels {
		if t == nil {
			continue
		}
		result.Connected++
		cleanup, err := gateway.InstallRoute(result.Sessions[i].Device, i)
		if err != nil {
			result.Sessions[i].Error = "route: " + err.Error()
			continue
		}
		routeCleanups = append(routeCleanups, cleanup)
	}
	parallel(len(tunnels), func(i int) {
		session := &result.Sessions[i]
		if tunnels[i] == nil || session.Error != "" {
			return
		}
		begin := time.Now()
		if err := fetchThrough(session.Device, target); err != nil {
			session.Error = "traffic: " + err.Error()
			return
		}
		session.TrafficMs = milliseconds(begin)
	})
	for i, session := range result.Sessions {
		if tunnels[i] != nil && session.Error == "" {
			result.TrafficOK++
		}
	}
	if err := sampleEngine(&result, tunnels); err != nil {
		result.Errors = append(result.Errors, "sample: "+err.Error())
	}

	parallel(len(tunnels), func(i int) {
		if tunnels[i] == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		begin := time.Now()
		err := tunnels[i].Close(ctx)
		result.Sessions[i].StopMs = milliseconds(begin)
		if err != nil {
			result.Sessions[i].Error = strings.TrimPrefix(result.Sessions[i].Error+"; stop: "+err.Error(), "; ")
		}
	})
	var connects []float64
	for i, session := range result.Sessions {
		if tunnels[i] == nil {
			continue
		}
		connects = append(connects, session.ConnectMs)
		result.MaxConnectMs = max(result.MaxConnectMs, session.ConnectMs)
		result.MaxStopMs = max(result.MaxStopMs, session.StopMs)
		if !strings.Contains(session.Error, "stop: ") {
			result.Stopped++
		}
	}
	if len(connects) > 0 {
		sort.Float64s(connects)
		result.MedianConnectMs = connects[len(connects)/2]
	}
	var cleanupErrs []error
	for _, cleanup := range routeCleanups {
		cleanupErrs = append(cleanupErrs, cleanup())
	}
	for _, session := range result.Sessions {
		if session.Error != "" {
			result.Errors = append(result.Errors, session.Device+": "+session.Error)
		}
	}
	return result, errors.Join(cleanupErrs...)
}

// sampleEngine records resources while every tunnel is still up and after
// traffic, so CPU covers handshakes plus the data path for both engines. CPU
// sums live threads only; both engines keep their threads until stopped.
func sampleEngine(result *report, tunnels []tunnel) error {
	var pids []string
	for _, t := range tunnels {
		if t != nil && t.PID() != 0 {
			pids = append(pids, fmt.Sprint(t.PID()))
		}
	}
	if result.Engine == "core" {
		pids = []string{"self"}
	}
	result.Processes = len(pids)
	for _, pid := range pids {
		stats, err := readProc(pid)
		if err != nil {
			return err
		}
		result.Threads += stats.threads
		result.RSSKB += stats.rssKB
		result.PSSKB += stats.pssKB
		result.PeakRSSKB += stats.peakKB
		result.CPUMs += stats.cpuMs
	}
	return nil
}

// fetchThrough sends one HTTP request from a socket bound to device and
// checks the server saw a VPN client address, proving the tunnel carried it.
func fetchThrough(device, target string) error {
	client := &http.Client{Transport: gateway.DeviceTransport(device), Timeout: 20 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "vpn-client=") {
		return fmt.Errorf("unexpected answer %d %q", response.StatusCode, body)
	}
	return nil
}

func parallel(count int, work func(int)) {
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			work(i)
		}(i)
	}
	wg.Wait()
}

func milliseconds(since time.Time) float64 {
	return float64(time.Since(since).Microseconds()) / 1000
}
