package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseGatewayList(t *testing.T) {
	req := parseGateway([]string{"--list"})
	if req.Action != "gateway_list" {
		t.Fatalf("expected gateway_list action, got %q", req.Action)
	}
	if req.GatewayID != "" {
		t.Fatalf("expected empty gateway id for list, got %q", req.GatewayID)
	}
}

func TestParseUserCreate(t *testing.T) {
	req := parseUser([]string{"create", "-u", "user-1", "--group", "sales"})
	if req.Action != "create_user" || req.UserID != "user-1" || req.Group != "sales" {
		t.Fatalf("unexpected create user request: %+v", req)
	}
}

func TestParseUserListFilters(t *testing.T) {
	req := parseUser([]string{"list", "-u", "sdl-??-*", "-n", "huang"})
	if req.Action != "list_users" || req.IDFilter != "sdl-??-*" || req.NameFilter != "huang" {
		t.Fatalf("unexpected list users request: %+v", req)
	}
}

func TestParseDeviceList(t *testing.T) {
	req := parseDevice([]string{"list", "-u", "user-1"})
	if req.Action != "list_device" || req.UserID != "user-1" {
		t.Fatalf("unexpected device list request: %+v", req)
	}
}

func TestParseDeviceIssueAuthTicket(t *testing.T) {
	req := parseDevice([]string{"issue-auth-ticket", "--id", "user-1", "--group", "sales", "--ttl-seconds", "600"})
	if req.Action != "issue_device_ticket" || req.UserID != "user-1" || req.Group != "sales" || req.TTLSeconds != 600 {
		t.Fatalf("unexpected issue auth ticket request: %+v", req)
	}
}

func TestParseDeviceExtendExpiry(t *testing.T) {
	req := parseDevice([]string{"extend-expiry", "-u", "user-1", "--device-id", "dev-1", "-t", "3600"})
	if req.Action != "extend_device_expiry" || req.UserID != "user-1" || req.DeviceID != "dev-1" || req.All || req.TTLSeconds != 3600 {
		t.Fatalf("unexpected extend expiry request: %+v", req)
	}
}

func TestParseDeviceExtendExpiryAll(t *testing.T) {
	req := parseDevice([]string{"extend-expiry", "--id", "user-1", "--all"})
	if req.Action != "extend_device_expiry" || req.UserID != "user-1" || !req.All || req.DeviceID != "" {
		t.Fatalf("unexpected extend all expiry request: %+v", req)
	}
}

func TestParseGatewayEnlist(t *testing.T) {
	req := parseGateway([]string{"--enlist", "gw-1"})
	if req.Action != "gateway_enlist" {
		t.Fatalf("expected gateway_enlist action, got %q", req.Action)
	}
	if req.GatewayID != "gw-1" {
		t.Fatalf("expected gateway id gw-1, got %q", req.GatewayID)
	}
}

func TestParseGatewayDelist(t *testing.T) {
	req := parseGateway([]string{"--delist", "gw-1"})
	if req.Action != "gateway_delist" {
		t.Fatalf("expected gateway_delist action, got %q", req.Action)
	}
	if req.GatewayID != "gw-1" {
		t.Fatalf("expected gateway id gw-1, got %q", req.GatewayID)
	}
}

func TestWriteResponseExtendDeviceExpiryShowsSummaryAndUpdatedDevices(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	resp := adminResponse{
		OK:           true,
		UpdatedCount: 1,
		UpdatedDevices: []deviceInfo{{
			UserID:           "u-1",
			Group:            "default.ms.net",
			Name:             "node-1",
			DeviceID:         "dev-1",
			AuthExpireAtUnix: 1_750_000_000,
		}},
		Devices: []deviceInfo{{
			UserID:           "u-1",
			Group:            "default.ms.net",
			Name:             "node-1",
			DeviceID:         "dev-1",
			AuthExpireAtUnix: 1_750_000_000,
		}},
	}
	if err := writeResponse(&stdout, &stderr, "extend_device_expiry", resp); err != nil {
		t.Fatalf("writeResponse failed: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"Extended device expiry",
		"Updated Count",
		"1",
		"Updated devices",
		"Current devices",
		"dev-1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestWriteResponseListUsers(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	resp := adminResponse{
		OK: true,
		Users: []userInfo{{
			UserID:        "sdl-user-1",
			Name:          "Example User",
			Email:         "user@example.com",
			Group:         "user.ms.net",
			Domain:        "ms.net",
			CreatedAtUnix: 1_750_000_000,
		}},
	}
	if err := writeResponse(&stdout, &stderr, "list_users", resp); err != nil {
		t.Fatalf("writeResponse failed: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"Users (1)", "USER ID", "NAME", "EMAIL", "GROUP", "DOMAIN", "sdl-user-1", "Example User", "user@example.com", "user.ms.net", "ms.net"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}
