package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sdl-control/config"
	"sdl-control/control"
)

func TestAdminHTTPAuthRejectsMissingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/list_devices?user_id=u1", nil)
	rr := httptest.NewRecorder()
	adminHTTPAuth("secret", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAdminHTTPListDevices(t *testing.T) {
	ctrl := newTestController(t)
	userID := "user-" + filepath.Base(t.TempDir()) + "-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	user, err := ctrl.UMCreateUserWithID(userID, "sales", "ms.net")
	if err != nil {
		t.Fatalf("create user failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/list_devices?user_id="+user.UserID, nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	adminHTTPAuth("secret", adminHTTPHandler(ctrl)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("expected ok response, got %s", rr.Body.String())
	}
}

func TestAdminHTTPListUsersWithFilter(t *testing.T) {
	ctrl := newTestController(t)
	for _, userID := range []string{"sdl-alpha", "sdl-beta", "admin-1"} {
		if _, err := ctrl.UMCreateUserWithID(userID, "sales", "ms.net"); err != nil {
			t.Fatalf("create user %s failed: %v", userID, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/list_users?filter=sdl-%3Feta", nil)
	rec := httptest.NewRecorder()
	adminHTTPHandler(ctrl).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	var resp adminResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK || len(resp.Users) != 1 || resp.Users[0].UserID != "sdl-beta" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func newTestController(t *testing.T) *control.Controller {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir failed: %v", err)
	}
	cfgJSON := `{
		"default_domain":"ms.net",
		"default_gateway_id":"default",
		"gateway_ticket_secret":"test-secret",
		"listen_addr":":443",
		"admin_http_addr":"127.0.0.1:8081",
		"admin_http_token":"secret",
		"domains":{"ms.net":{"groups":{"sales":{"gateway":"10.26.0.1","netmask":"255.255.255.0","dns_service_ip":"10.26.0.53"}}}}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	testSnapshot, err := os.ReadFile(filepath.Join("testdata", "um.json"))
	if err != nil {
		t.Fatalf("read test um snapshot failed: %v", err)
	}
	umPath := filepath.Join(dataDir, "um.json")
	if err := os.WriteFile(umPath, testSnapshot, 0o644); err != nil {
		t.Fatalf("write test um snapshot failed: %v", err)
	}
	t.Setenv("UM_STORE_JSON_PATH", umPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	ctrl, err := control.NewController(cfg, nil)
	if err != nil {
		t.Fatalf("new controller failed: %v", err)
	}
	t.Cleanup(func() {
		ctrl.Stop()
		_ = context.Background()
	})
	return ctrl
}
