package web

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

func (s *Server) connect(w http.ResponseWriter, r *http.Request, id string) {
	if !s.Runtime.Catalog.TryMaintenance() {
		respondError(w, errors.New("当前已有节点测试或维护任务"))
		return
	}
	defer s.Runtime.Catalog.EndMaintenance()
	node, err := s.Runtime.Catalog.ByID(id)
	if err != nil {
		respondError(w, err)
		return
	}
	if _, err := s.Runtime.Catalog.Test(r.Context(), id); err != nil {
		respondError(w, err)
		return
	}
	cfg := s.Store.Snapshot()
	cfg.FixedNodeID = node.String("id")
	cfg.RoutingMode = "fixed_ip"
	cfg.ConnectionEnabled = true
	if _, err := s.Store.Save(cfg); err != nil {
		respondError(w, err)
		return
	}
	s.Runtime.Pool.Invalidate()
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"ok": true, "message": "节点已通过原生握手并设为固定节点；新连接将使用选定的隧道",
		"session_username": fmt.Sprintf("session-%s-t-30", gateway.ParsePublicID("fixed-"+id)),
	})
}
