package web

import (
	"context"
	"errors"
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

func (r *Runtime) ConnectNode(id string) error {
	if r.Catalog != nil {
		node, err := r.Catalog.ByID(id)
		if err != nil {
			return err
		}
		cfg := r.Store.Snapshot()
		cfg.FixedNodeID = node.String("id")
		cfg.RoutingMode = "fixed_ip"
		cfg.ConnectionEnabled = true
		_, err = r.Store.Save(cfg)
		return err
	}
	return errors.New("node catalog unavailable")
}

func (r *Runtime) Disconnect(disable bool) error {
	cfg := r.Store.Snapshot()
	cfg.ConnectionEnabled = !disable
	if _, err := r.Store.Save(cfg); err != nil {
		return err
	}
	if disable {
		r.setMessage("已拒绝新的代理连接；存活连接与隧道按各自生命周期回收")
	} else {
		r.setMessage("已允许新的代理连接")
	}
	return nil
}

func (r *Runtime) State() map[string]any {
	state := r.Store.State()
	assigned, spare, sessions := r.Pool.Status()
	r.mu.RLock()
	health, message := r.ProxyHealth, r.Message
	connecting := r.Connecting
	r.mu.RUnlock()
	cfg := state["connection_enabled"] == true
	tunnelReady := len(sessions)+len(spare) > 0
	state["tunnel_ready"] = cfg && tunnelReady
	state["proxy_ready"] = cfg && health.OK
	state["proxy_ok"] = cfg && health.OK
	state["proxy_ip"] = health.IP
	state["proxy_latency_ms"] = health.LatencyMS
	state["proxy_error"] = health.Error
	state["last_check_message"] = message
	state["is_connecting"] = connecting
	state["assigned_sessions"] = assigned
	state["active_tunnel_count"] = len(sessions)
	state["spare_tunnel_count"] = len(spare)
	state["pending_tunnels"] = r.Pool.Pending()
	state["active_openvpn_node_id"] = r.ActiveNode()
	state["app_version"] = AppVersion
	state["app_version_label"] = "V" + AppVersion + " Go 原生版"
	state["deployment_mode"] = "go"
	state["deployment_mode_label"] = "Go + OpenVPN 3 Core"
	state["target_valid_nodes"] = min(4, len(sessions)+len(spare))
	state["api_url"] = "https://www.vpngate.net/api/iphone/"
	state["mirror_url"] = "https://limliu.github.io/vpngate-proxy/vpngate.csv"
	state["fav_fail_fallback"] = false
	state["maintenance_running"] = false
	return state
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

func (r *Runtime) Services() []map[string]any {
	assigned, spare, sessions := r.Pool.Status()
	nativeRunning := len(sessions)+len(spare) > 0
	r.mu.RLock()
	lastCheck, lastDiscovery, lastPing := r.LastCheck, r.LastDiscovery, r.LastPing
	r.mu.RUnlock()
	nativeState := "stopped"
	if nativeRunning {
		nativeState = "running"
	}
	return []map[string]any{
		{"name": "Web 管理服务", "status": "running", "details": "Go net/http 管理服务", "error": ""},
		{"name": "本地代理网关", "status": "running", "details": r.ListenerAddr, "error": ""},
		{"name": "OpenVPN 3 原生连接池", "status": nativeState,
			"details": fmt.Sprintf("会话 %d，可用备用隧道 %d，创建中 %d", assigned, len(spare), r.Pool.Pending()), "error": ""},
		{"name": "节点同步守护线程", "status": healthyDaemon(lastDiscovery, r.Started, 1*time.Hour), "details": lastDiscovery.String(), "error": ""},
		{"name": "出口检测守护线程", "status": healthyDaemon(lastCheck, r.Started, 90*time.Second), "details": lastCheck.String(), "error": ""},
		{"name": "延迟测速守护线程", "status": healthyDaemon(lastPing, r.Started, 45*time.Second), "details": lastPing.String(), "error": ""},
	}
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

func healthyDaemon(last, since time.Time, maximum time.Duration) string {
	if time.Since(last) <= maximum || time.Since(since) <= maximum {
		return "running"
	}
	return "stopped"
}
