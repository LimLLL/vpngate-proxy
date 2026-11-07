package web

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

func (s *Server) get(w http.ResponseWriter, r *http.Request, path string) {
	switch path {
	case "/", "/index.html":
		s.serveAsset(w, "static/index.html")
	case "/api/nodes":
		nodes := s.Runtime.Catalog.Nodes()
		_, _, sessions := s.Runtime.Pool.Status()
		used := make(map[string]bool, len(sessions))
		for _, session := range sessions {
			used[session.NodeID] = true
		}
		for _, node := range nodes {
			node["active"] = used[node.String("id")]
			delete(node, "config_text")
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"nodes": nodes, "state": s.Runtime.State()})
	case "/api/gateway_status":
		writeJSONResponse(w, http.StatusOK, map[string]any{"ok": true, "services": s.Runtime.Services()})
	case "/api/logs":
		writeJSONResponse(w, http.StatusOK, map[string]any{"logs": recentLogs(s.Store.Dir)})
	case "/api/check_update":
		result, err := checkLatestRelease(r.Context())
		if err != nil {
			writeJSONResponse(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSONResponse(w, http.StatusOK, result)
	default:
		if strings.HasPrefix(path, "/configs/") {
			filename := filepath.Base(path[len("/configs/"):])
			for _, node := range s.Runtime.Catalog.Nodes() {
				if filepath.Base(node.String("config_file")) == filename {
					w.Header().Set("Content-Type", "application/x-openvpn-profile")
					_, _ = io.WriteString(w, node.String("config_text"))
					return
				}
			}
		}
		writeJSONResponse(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}
