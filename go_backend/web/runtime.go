package web

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

type ProxyHealth struct {
	OK        bool   `json:"ok"`
	IP        string `json:"ip,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// Runtime owns actual pool readiness, background refresh and public egress.
type Runtime struct {
	Catalog *Catalog
	Pool    *gateway.Pool
	Proxy   *gateway.Proxy
	Store   *DataStore

	mu            sync.RWMutex
	LastCheck     time.Time
	LastDiscovery time.Time
	LastPing      time.Time
	ProxyHealth   ProxyHealth
	Message       string
	Connecting    bool
	ListenerAddr  string
	Started       time.Time
}

func NewRuntime(catalog *Catalog, pool *gateway.Pool) *Runtime {
	return &Runtime{Catalog: catalog, Pool: pool, Store: catalog.Store, Started: time.Now(), Message: "Go 原生网关已启动"}
}

func (r *Runtime) Maintain(ctx context.Context, interval time.Duration) {
	if interval < time.Second {
		interval = 20 * time.Minute
	}
	r.checkDiscovery(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.checkDiscovery(ctx)
		}
	}
}

func (r *Runtime) checkDiscovery(ctx context.Context) {
	if r.Catalog.TryMaintenance() {
		defer r.Catalog.EndMaintenance()
		r.setConnecting(true)
		defer r.setConnecting(false)
		r.Message = "正在同步 VPNGate 候选节点"
		if err := r.Catalog.Refresh(ctx); err != nil {
			r.setMessage("节点同步失败：" + err.Error())
			log.Printf("node discovery: %v", err)
		} else {
			r.setMessage("节点目录已同步，原生活动隧道保持运行")
			r.mu.Lock()
			r.LastDiscovery = time.Now()
			r.mu.Unlock()
		}
	}
}

func (r *Runtime) setConnecting(connecting bool) {
	r.mu.Lock()
	r.Connecting = connecting
	r.mu.Unlock()
}

func (r *Runtime) setMessage(message string) {
	r.mu.Lock()
	r.Message = message
	r.mu.Unlock()
	if r.Store != nil {
		_ = r.Store.SetState(map[string]any{"last_check_message": message})
	}
}

// CheckPublicEgress sends a real request through the selected native TUN and
// verifies that the returned public address is not merely an internal VPN IP.
func (r *Runtime) CheckPublicEgress(ctx context.Context, session string) (ProxyHealth, error) {
	if session == "" {
		session = "webcheck"
	}
	lease, err := r.Pool.Acquire(ctx, gateway.SessionSpec{ID: session, TTL: 30 * time.Minute})
	if err != nil {
		return ProxyHealth{Error: err.Error()}, err
	}
	defer lease.Release()
	dialer := gateway.DeviceDialer{Device: lease.Info.TUNName, DNS: "8.8.8.8"}
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			var port int
			if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
				return nil, fmt.Errorf("invalid egress port: %w", err)
			}
			return dialer.DialContext(ctx, host, port)
		},
	}
	defer transport.CloseIdleConnections()
	var all []string
	for _, address := range []string{"https://api.ipify.org", "http://ip.sb"} {
		started := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			continue
		}
		response, err := transport.RoundTrip(req)
		if err != nil {
			all = append(all, err.Error())
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
		_ = response.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if readErr != nil || response.StatusCode != http.StatusOK || ip == nil || ip.IsPrivate() {
			all = append(all, fmt.Sprintf("%s returned an invalid egress", address))
			continue
		}
		result := ProxyHealth{OK: true, IP: ip.String(), LatencyMS: time.Since(started).Milliseconds()}
		r.mu.Lock()
		r.LastCheck, r.ProxyHealth = time.Now(), result
		r.mu.Unlock()
		return result, nil
	}
	err = fmt.Errorf("real public egress request failed: %s", strings.Join(all, "; "))
	r.mu.Lock()
	r.LastCheck, r.ProxyHealth = time.Now(), ProxyHealth{Error: err.Error()}
	r.mu.Unlock()
	return ProxyHealth{Error: err.Error()}, err
}

func (r *Runtime) ActiveNode() string {
	if !r.Store.Snapshot().ConnectionEnabled {
		return ""
	}
	_, _, sessions := r.Pool.Status()
	cfg := r.Store.Snapshot()
	for _, session := range sessions {
		if cfg.FixedNodeID != "" && session.NodeID == cfg.FixedNodeID {
			return session.NodeID
		}
	}
	if len(sessions) > 0 {
		return sessions[0].NodeID
	}
	return ""
}

// SetPingResult records a physical-transport probe, not tunneled application RTT.
func (r *Runtime) SetPingResult(latency int) {
	r.mu.Lock()
	r.LastPing = time.Now()
	r.mu.Unlock()
	display := "检测超时"
	if latency > 0 {
		display = fmt.Sprintf("%d ms", latency)
	}
	_ = r.Store.SetState(map[string]any{"active_node_latency": display})
}
