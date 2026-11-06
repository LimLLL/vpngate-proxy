package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

type options struct {
	profiles     []string
	readyFile    string
	stopFile     string
	reportFile   string
	stopDeadline time.Duration
}

type sessionReport struct {
	Device      string              `json:"device"`
	ConfigureMs float64             `json:"configure_ms"`
	ConnectMs   float64             `json:"connect_ms"`
	CloseMs     float64             `json:"close_ms"`
	Info        core.ConnectionInfo `json:"info"`
	Error       string              `json:"error,omitempty"`
}

type runReport struct {
	Backend                 string          `json:"backend"`
	CoreVersion             string          `json:"core_version"`
	Concurrency             int             `json:"concurrency"`
	Stage                   string          `json:"stage"`
	Sessions                []sessionReport `json:"sessions"`
	MaxReadyMs              float64         `json:"max_ready_ms"`
	WallReadyMs             float64         `json:"wall_ready_ms"`
	EngineProcessCount      int             `json:"engine_process_count"`
	ThreadsAfterConnect     int             `json:"threads_after_connect"`
	CurrentRSSKBAfterActive int             `json:"current_rss_kb_after_connect"`
	PeakRSSKB               int             `json:"peak_rss_kb"`
	CPUMs                   float64         `json:"cpu_ms"`
	Errors                  []string        `json:"errors,omitempty"`
}

type sessionResult struct {
	index     int
	connectMs float64
	info      core.ConnectionInfo
	err       error
}

type resources struct {
	threads int
	rssKB   int
	peakKB  int
}

func elapsedMs(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func cpuMilliseconds() (float64, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	seconds := float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	return seconds * 1000, nil
}

func statusValue(text, key string) (int, error) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, key+":") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("unexpected %s value %q", key, line)
			}
			return strconv.Atoi(fields[1])
		}
	}
	return 0, fmt.Errorf("%s is absent from /proc/self/status", key)
}

func processResources() (resources, error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return resources{}, err
	}
	var result resources
	values := []struct {
		name   string
		target *int
	}{{"Threads", &result.threads}, {"VmRSS", &result.rssKB}, {"VmHWM", &result.peakKB}}
	for _, value := range values {
		parsed, err := statusValue(string(raw), value.name)
		if err != nil {
			return resources{}, err
		}
		*value.target = parsed
	}
	return result, nil
}

func writeReport(path string, report runReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func closeAll(clients []*core.Client, report *runReport) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var stopErrors []error
	for index, client := range clients {
		if client == nil {
			continue
		}
		wg.Add(1)
		go func(index int, client *core.Client) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			started := time.Now()
			err := client.Close(ctx)
			mu.Lock()
			report.Sessions[index].CloseMs = elapsedMs(started)
			mu.Unlock()
			if err != nil {
				mu.Lock()
				report.Sessions[index].Error = err.Error()
				stopErrors = append(stopErrors, fmt.Errorf("%s: %w", report.Sessions[index].Device, err))
				mu.Unlock()
			}
		}(index, client)
	}
	wg.Wait()
	return errors.Join(stopErrors...)
}

// connectAll prepares every profile before starting the concurrent handshakes.
func connectAll(opts options, clients []*core.Client, report *runReport) error {
	for index, path := range opts.profiles {
		profile, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		device := fmt.Sprintf("tun%d", index)
		report.Sessions[index].Device = device
		started := time.Now()
		client, err := core.NewClient(string(profile), "vpn", "vpn", 15)
		report.Sessions[index].ConfigureMs = elapsedMs(started)
		if err != nil {
			return fmt.Errorf("configure %s: %w", device, err)
		}
		clients[index] = client
		client.OnEvent = func(event core.Event) {
			if event.Error || event.Fatal {
				fmt.Printf("%s event: %+v\n", device, event)
			}
		}
	}

	responses := make(chan sessionResult, len(clients))
	for index, client := range clients {
		go func(index int, client *core.Client) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			started := time.Now()
			info, err := client.Connect(ctx)
			responses <- sessionResult{index: index, connectMs: elapsedMs(started), info: info, err: err}
		}(index, client)
	}

	var connectErrors []error
	for range clients {
		result := <-responses
		report.Sessions[result.index].ConnectMs = result.connectMs
		if result.err != nil {
			report.Sessions[result.index].Error = result.err.Error()
			connectErrors = append(connectErrors, result.err)
			continue
		}
		expected := fmt.Sprintf("tun%d", result.index)
		if result.info.TUNName != expected {
			err := fmt.Errorf("expected %s, got %s", expected, result.info.TUNName)
			report.Sessions[result.index].Error = err.Error()
			connectErrors = append(connectErrors, err)
			continue
		}
		report.Sessions[result.index].Info = result.info
	}
	return errors.Join(connectErrors...)
}

func waitForStop(path string, deadline time.Duration) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			_, err := os.Stat(path)
			if err == nil {
				return nil
			}
			if !os.IsNotExist(err) {
				return fmt.Errorf("check stop file: %w", err)
			}
		case <-timeout.C:
			return fmt.Errorf("external traffic check did not finish within %s", deadline)
		}
	}
}

func main() {
	profileList := flag.String("profiles", "", "comma-separated prepared profile paths")
	readyFile := flag.String("ready-file", "", "file created after every tunnel is ready")
	stopFile := flag.String("stop-file", "", "file requesting benchmark shutdown")
	reportFile := flag.String("report", "", "path for the benchmark JSON report")
	stopDeadline := flag.Duration("stop-deadline", 60*time.Second, "maximum wait for the external traffic check")
	flag.Parse()
	paths := strings.Split(*profileList, ",")
	if *profileList == "" || len(paths) < 1 || len(paths) > 4 || *readyFile == "" || *stopFile == "" || *reportFile == "" {
		flag.Usage()
		log.Fatal("one to four profiles and ready, stop and report paths are required")
	}

	started := time.Now()
	cpuStart, err := cpuMilliseconds()
	if err != nil {
		log.Fatal(err)
	}
	report := runReport{
		Backend: "go-openvpn3-core", CoreVersion: core.Platform(), Concurrency: len(paths),
		Stage: "starting", Sessions: make([]sessionReport, len(paths)), EngineProcessCount: 1,
	}
	clients := make([]*core.Client, len(paths))
	var resultErr error
	if err := connectAll(options{profiles: paths}, clients, &report); err != nil {
		resultErr = err
		report.Stage = "connect_failed"
	} else {
		report.MaxReadyMs = 0
		for _, session := range report.Sessions {
			report.MaxReadyMs = max(report.MaxReadyMs, session.ConnectMs)
		}
		report.WallReadyMs = elapsedMs(started)
		resources, err := processResources()
		if err != nil {
			resultErr = err
			report.Stage = "metrics_failed"
		} else {
			report.ThreadsAfterConnect = resources.threads
			report.CurrentRSSKBAfterActive = resources.rssKB
			report.PeakRSSKB = resources.peakKB
			report.Stage = "connected"
			if err := writeReport(*reportFile, report); err != nil {
				resultErr = err
			} else if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o600); err != nil {
				resultErr = fmt.Errorf("write ready file: %w", err)
			} else {
				resultErr = waitForStop(*stopFile, *stopDeadline)
				if resultErr != nil {
					report.Stage = "external_check_failed"
				}
			}
		}
	}

	// Sample before SIGTERM/native stop in both backends. Process-wide CPU
	// includes the Go controller, Core and handshake/data-plane activity; the
	// CLI reports the equivalent cumulative CPU of its OpenVPN child PIDs.
	cpuEnd, err := cpuMilliseconds()
	if err != nil {
		resultErr = errors.Join(resultErr, err)
	} else {
		report.CPUMs = cpuEnd - cpuStart
	}
	if err := closeAll(clients, &report); err != nil {
		resultErr = errors.Join(resultErr, err)
		report.Stage = "stop_failed"
	} else if resultErr == nil {
		report.Stage = "stopped"
	}
	if finalResources, err := processResources(); err != nil {
		resultErr = errors.Join(resultErr, err)
	} else {
		report.PeakRSSKB = max(report.PeakRSSKB, finalResources.peakKB)
	}
	report.Errors = report.Errors[:0]
	for _, session := range report.Sessions {
		if session.Error != "" {
			report.Errors = append(report.Errors, session.Device+": "+session.Error)
		}
	}
	if resultErr != nil {
		report.Errors = append(report.Errors, resultErr.Error())
	}
	if err := writeReport(*reportFile, report); err != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("write benchmark report: %w", err))
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
	if resultErr != nil {
		log.Fatal(resultErr)
	}
}
