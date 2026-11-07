package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const AppVersion = "2.1.5"

//go:embed static/login.html static/index.html
var assets embed.FS

type Server struct {
	Runtime *Runtime
	Store   *DataStore
	Root    context.Context
	Restart func()

	mu       sync.Mutex
	sessions map[string]time.Time
}

func NewServer(root context.Context, runtime *Runtime) *Server {
	if runtime == nil || runtime.Store == nil {
		panic("management runtime and data store are required")
	}
	return &Server{Runtime: runtime, Store: runtime.Store, Root: root, sessions: make(map[string]time.Time)}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	path := r.URL.Path
	prefix := s.Store.Snapshot().SecretPath
	if prefix != "" {
		if path == "/"+prefix {
			http.Redirect(w, r, "/"+prefix+"/", http.StatusFound)
			return
		}
		if !strings.HasPrefix(path, "/"+prefix+"/") {
			writeJSONResponse(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		path = "/" + strings.TrimPrefix(path, "/"+prefix+"/")
	}
	if r.Method == http.MethodPost && path == "/api/login" {
		s.login(w, r)
		return
	}
	if r.Method == http.MethodPost && path == "/api/logout" {
		s.logout(w, r, prefix)
		return
	}
	if !s.authorized(r) {
		if r.Method == http.MethodGet && (path == "/" || path == "/index.html") {
			s.serveAsset(w, "static/login.html")
			return
		}
		writeJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "Unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.get(w, r, path)
	case http.MethodPost:
		s.post(w, r, path)
	default:
		writeJSONResponse(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) authorized(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" || s.Store.Snapshot().Password == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[cookie.Value]
	if ok && now.Before(expiry) {
		return true
	}
	delete(s.sessions, cookie.Value)
	for token, expires := range s.sessions {
		if now.After(expires) {
			delete(s.sessions, token)
		}
	}
	return false
}

func cookiePath(secret string) string {
	if secret == "" {
		return "/"
	}
	return "/" + secret + "/"
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	body, err := decodeBody(r, 4096)
	if err != nil {
		respondError(w, err)
		return
	}
	cfg := s.Store.Snapshot()
	valid := cfg.Password != "" &&
		subtle.ConstantTimeCompare([]byte(body["username"].text()), []byte(cfg.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(body["password"].text()), []byte(cfg.Password)) == 1
	if !valid {
		writeJSONResponse(w, http.StatusForbidden, map[string]any{"ok": false, "error": "用户名或密码不正确"})
		return
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		respondError(w, err)
		return
	}
	token := hex.EncodeToString(value)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(30 * 24 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: cookiePath(cfg.SecretPath),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, prefix string) {
	if cookie, err := r.Cookie("session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Path: cookiePath(prefix), HttpOnly: true,
		MaxAge: -1, Expires: time.Unix(0, 0), SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) serveAsset(w http.ResponseWriter, name string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		respondError(w, err)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) post(w http.ResponseWriter, r *http.Request, path string) {
	body, err := decodeBody(r, 65536)
	if err != nil {
		respondError(w, err)
		return
	}
	switch path {
	case "/api/update_credentials":
		s.updateCredentials(w, body)
	case "/api/update_settings":
		cfg := s.Store.Snapshot()
		cfg.ProxyPort = body["proxy_port"].integer()
		s.updateSettings(w, body, cfg, true)
	case "/api/update_routing":
		cfg := s.Store.Snapshot()
		s.updateSettings(w, body, cfg, false)
	case "/api/toggle_favorite":
		s.toggleFavorite(w, body)
	case "/api/check":
		if !s.Runtime.Catalog.TryMaintenance() {
			writeJSONResponse(w, http.StatusConflict, map[string]any{"ok": false, "error": "节点维护任务正在运行"})
			return
		}
		defer s.Runtime.Catalog.EndMaintenance()
		if err := s.Runtime.Catalog.Refresh(r.Context()); err != nil {
			respondError(w, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "message": "节点同步完成"})
	case "/api/refresh_nodes":
		s.refreshNodes(w, body)
	case "/api/test_nodes":
		s.testNodes(w, r, body)
	case "/api/test_node":
		s.testNode(w, r, body["id"].text())
	case "/api/test_proxy":
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		result, err := s.Runtime.CheckPublicEgress(ctx, "webcheck")
		if err != nil {
			writeJSONResponse(w, http.StatusOK, result)
			return
		}
		writeJSONResponse(w, http.StatusOK, result)
	case "/api/connect":
		s.connect(w, r, body["id"].text())
	case "/api/disconnect":
		err := s.Runtime.Disconnect(true)
		if err != nil {
			respondError(w, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSONResponse(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func respondError(w http.ResponseWriter, err error) {
	log.Printf("api: %v", err)
	writeJSONResponse(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func decodeBody(r *http.Request, maximum int) (map[string]requestValue, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(maximum+1)))
	if err != nil || len(data) > maximum {
		return nil, errors.New("invalid or oversized JSON request")
	}
	if len(data) == 0 {
		return map[string]requestValue{}, nil
	}
	var decoded map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	output := make(map[string]requestValue, len(decoded))
	for key, value := range decoded {
		output[key] = requestValue{value: value}
	}
	return output, nil
}

type requestValue struct{ value any }

func (v requestValue) text() string {
	if v.value == nil {
		return ""
	}
	return fmt.Sprint(v.value)
}

func (v requestValue) integer() int {
	switch value := v.value.(type) {
	case json.Number:
		result, err := value.Int64()
		if err == nil {
			return int(result)
		}
	case float64:
		return int(value)
	case string:
		var result int
		_, _ = fmt.Sscanf(value, "%d", &result)
		return result
	}
	return 0
}

func (v requestValue) strings() []any {
	if result, ok := v.value.([]any); ok {
		return result
	}
	return nil
}

func (s *Server) updateCredentials(w http.ResponseWriter, body map[string]requestValue) {
	current := s.Store.Snapshot()
	username := strings.TrimSpace(body["username"].text())
	password := body["password"].text()
	port := body["port"].integer()
	suffix := strings.TrimSpace(body["secret_path"].text())
	if username == "" || (password == "" && current.Password == "") {
		respondError(w, errors.New("用户名不能为空；首次设置密码也不能为空"))
		return
	}
	if port < 1 || port > 65535 || port == current.ProxyPort {
		respondError(w, errors.New("插件管理端口无效或与代理端口冲突"))
		return
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(suffix) {
		respondError(w, errors.New("安全路径只能是英文字母和数字"))
		return
	}
	changedPassword := password != "" && password != current.Password
	reauthRequired := changedPassword || username != current.Username
	oldPort, oldSuffix := current.Port, current.SecretPath
	current.Username = username
	if password != "" {
		current.Password = password
	}
	current.Port, current.SecretPath = port, suffix
	_, err := s.Store.Save(current)
	if err != nil {
		respondError(w, err)
		return
	}
	if password != "" {
		s.Runtime.Proxy.SetPassword(password)
	}
	if reauthRequired {
		s.mu.Lock()
		s.sessions = make(map[string]time.Time)
		s.mu.Unlock()
	}
	restart := port != oldPort || suffix != oldSuffix
	if restart && s.Restart != nil {
		time.AfterFunc(100*time.Millisecond, s.Restart)
	}
	if restart {
		writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "restart_needed": true, "reauth_required": changedPassword})
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "restart_needed": false, "reauth_required": changedPassword})
}

func (s *Server) updateSettings(w http.ResponseWriter, body map[string]requestValue, cfg Config, includePort bool) {
	mode := nonempty(body["routing_mode"].text(), cfg.RoutingMode)
	if mode != "auto" && mode != "fixed_ip" && mode != "fixed_region" && mode != "favorites" {
		respondError(w, errors.New("无效的路由配置模式"))
		return
	}
	kind := body["routing_ip_type"].text()
	if kind == "" {
		kind = cfg.RoutingIPType
	}
	if kind != "all" && kind != "residential" && kind != "hosting" {
		respondError(w, errors.New("无效的 IP 类型过滤"))
		return
	}
	if includePort && (cfg.ProxyPort < 1024 || cfg.ProxyPort > 65535 || cfg.ProxyPort == cfg.Port) {
		respondError(w, errors.New("代理端口无效或与 Web 端口冲突"))
		return
	}
	cfg.RoutingMode, cfg.RoutingIPType = mode, kind
	cfg.ForceCountry = strings.ToUpper(strings.TrimSpace(body["force_country"].text()))
	cfg.FavFailFallback = false
	if mode == "fixed_ip" && cfg.FixedNodeID == "" {
		respondError(w, errors.New("固定 IP 模式需要先选择一个可用节点"))
		return
	}
	if mode == "fixed_region" && !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(cfg.ForceCountry) {
		respondError(w, errors.New("固定地区模式需要有效的两字母国家代码"))
		return
	}
	cfg.ConnectionEnabled = true
	if _, err := s.Store.Save(cfg); err != nil {
		respondError(w, err)
		return
	}
	s.Runtime.Pool.Invalidate()
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "message": "路由配置已应用到新的代理连接"})
}

func (s *Server) toggleFavorite(w http.ResponseWriter, body map[string]requestValue) {
	id := body["id"].text()
	if _, err := s.Runtime.Catalog.ByID(id); err != nil {
		respondError(w, err)
		return
	}
	cfg := s.Store.Snapshot()
	seen := map[string]bool{}
	ids := make([]string, 0, len(cfg.FavoriteNodeIDs)+1)
	for _, saved := range cfg.FavoriteNodeIDs {
		if saved != id && !seen[saved] {
			ids = append(ids, saved)
			seen[saved] = true
		}
	}
	if !seen[id] {
		ids = append(ids, id)
	}
	cfg.FavoriteNodeIDs = ids
	if _, err := s.Store.Save(cfg); err != nil {
		respondError(w, err)
		return
	}
	if cfg.RoutingMode == "favorites" {
		s.Runtime.Pool.Invalidate()
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "favorite_node_ids": ids})
}

func (s *Server) refreshNodes(w http.ResponseWriter, body map[string]requestValue) {
	if values, ok := body["discovery_countries"]; ok {
		parts, ok := values.([]any)
		if !ok {
			respondError(w, errors.New("国家筛选范围必须是国家代码数组"))
			return
		}
		cfg := s.Store.Snapshot()
		cfg.DiscoveryCountries = normalizeCountries(parts)
		if _, err := s.Store.Save(cfg); err != nil {
			respondError(w, err)
			return
		}
	}
	if !s.Runtime.Catalog.TryMaintenance() {
		writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "running": true, "message": "节点维护任务已在运行"})
		return
	}
	go func() {
		defer s.Runtime.Catalog.EndMaintenance()
		if err := s.Runtime.Catalog.Refresh(s.Root); err != nil {
			log.Printf("refresh nodes: %v", err)
			return
		}
		s.Runtime.setMessage("已更新 Go 节点目录")
	}()
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "running": true})
}

func (s *Server) testNode(w http.ResponseWriter, r *http.Request, id string) {
	if !s.Runtime.Catalog.TryMaintenance() {
		respondError(w, errors.New("当前已有节点测试或维护任务"))
		return
	}
	defer s.Runtime.Catalog.EndMaintenance()
	node, err := s.Runtime.Catalog.Test(r.Context(), id)
	if err != nil {
		respondError(w, err)
		return
	}
	delete(node, "config_text")
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "node": node})
}

func (s *Server) testNodes(w http.ResponseWriter, r *http.Request, body map[string]requestValue) {
	values := body["ids"].strings()
	if len(values) > 20 {
		respondError(w, errors.New("ids 必须是最多 20 个节点 ID 的数组"))
		return
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		ids = append(ids, value.text())
	}
	if !s.Runtime.Catalog.TryMaintenance() {
		respondError(w, errors.New("当前已有节点测试或维护任务"))
		return
	}
	defer s.Runtime.Catalog.EndMaintenance()
	nodes, err := s.Runtime.Catalog.TestIDs(r.Context(), ids)
	if err != nil {
		respondError(w, err)
		return
	}
	for _, node := range nodes {
		delete(node, "config_text")
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "nodes": nodes})
}
