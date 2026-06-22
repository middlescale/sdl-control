package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"sdl-control/control"

	log "github.com/sirupsen/logrus"
)

func StartAdminHTTPServer(ctx context.Context, ctrl *control.Controller, addr string, token string, version string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin http listen %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/admin/v1/", adminHTTPAuth(token, adminHTTPHandler(ctrl, version)))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
			log.Warnf("admin HTTP server shutdown failed: %v", err)
		}
	}()
	go func() {
		log.Infof("admin HTTP server listening on %s", addr)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Errorf("admin HTTP server error: %v", err)
		}
	}()
	return nil
}

func adminHTTPAuth(token string, next http.Handler) http.Handler {
	expected := "Bearer " + strings.TrimSpace(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("Authorization")) != expected {
			writeAdminHTTPJSON(w, http.StatusUnauthorized, adminResponse{OK: false, Error: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

var adminReadActions = map[string]bool{
	"gateway_list": true,
	"list_gateway": true,
	"list_device":  true,
	"list_devices": true,
	"list_users":   true,
	"dns_domains":  true,
	"dns_snapshot": true,
	"version":      true,
}

func adminHTTPHandler(ctrl *control.Controller, version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeAdminHTTPJSON(w, http.StatusMethodNotAllowed, adminResponse{OK: false, Error: "method not allowed"})
			return
		}
		action := strings.TrimPrefix(r.URL.Path, "/admin/v1/")
		action = strings.Trim(action, "/")
		if r.Method != http.MethodPost && !adminReadActions[action] {
			writeAdminHTTPJSON(w, http.StatusMethodNotAllowed, adminResponse{OK: false, Error: "this action requires POST"})
			return
		}
		req, err := adminRequestFromHTTP(r)
		if err != nil {
			writeAdminHTTPJSON(w, http.StatusBadRequest, adminResponse{OK: false, Error: err.Error()})
			return
		}
		writeAdminHTTPJSON(w, http.StatusOK, executeAdminRequest(ctrl, version, req))
	})
}

func adminRequestFromHTTP(r *http.Request) (adminRequest, error) {
	action := strings.TrimPrefix(r.URL.Path, "/admin/v1/")
	action = strings.Trim(action, "/")
	req := adminRequest{Action: action}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		req.UserID = q.Get("user_id")
		req.IDFilter = q.Get("id")
		req.NameFilter = q.Get("name")
		req.Group = q.Get("group")
		req.DeviceID = q.Get("device_id")
		req.Domain = q.Get("domain")
		req.Name = q.Get("name")
		return req, nil
	}
	defer r.Body.Close()
	if r.ContentLength == 0 {
		return req, nil
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return adminRequest{}, err
	}
	if strings.TrimSpace(req.Action) == "" {
		req.Action = action
	}
	return req, nil
}

func writeAdminHTTPJSON(w http.ResponseWriter, status int, resp adminResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
