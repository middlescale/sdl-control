package handlers

import (
	"encoding/json"

	"sdl-control/control"
)

type adminRequest struct {
	Action       string   `json:"action"`
	Name         string   `json:"name,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	GatewayID    string   `json:"gateway_id,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Sections     []string `json:"sections,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	IDFilter     string   `json:"id_filter,omitempty"`
	NameFilter   string   `json:"name_filter,omitempty"`
	Group        string   `json:"group,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	All          bool     `json:"all,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
	TimeoutSec   int64    `json:"timeout_sec,omitempty"`
	DurationSec  int64    `json:"duration_sec,omitempty"`
}

type adminResponse struct {
	OK             bool                        `json:"ok"`
	Version        string                      `json:"version,omitempty"`
	UserID         string                      `json:"user_id,omitempty"`
	SdlUserID      string                      `json:"sdl_user_id,omitempty"`
	Name           string                      `json:"name,omitempty"`
	Domain         string                      `json:"domain,omitempty"`
	Group          string                      `json:"group,omitempty"`
	Domains        []string                    `json:"domains,omitempty"`
	Ticket         string                      `json:"ticket,omitempty"`
	ExpireAtUnix   int64                       `json:"expire_at_unix,omitempty"`
	Gateways       []control.GatewayAdminView  `json:"gateways,omitempty"`
	ExitNodes      []control.ExitNodeAdminView `json:"exit_nodes,omitempty"`
	Users          []control.UMUserAdminView   `json:"users,omitempty"`
	Devices        []control.DeviceAdminView   `json:"devices,omitempty"`
	UpdatedDevices []control.DeviceAdminView   `json:"updated_devices,omitempty"`
	DNSSnapshot    *control.DNSSnapshotView    `json:"dns_snapshot,omitempty"`
	DebugResult    json.RawMessage             `json:"debug_result,omitempty"`
	DebugPath      string                      `json:"debug_path,omitempty"`
	DebugWatchID   uint64                      `json:"debug_watch_id,omitempty"`
	UpdatedCount   int                         `json:"updated_count,omitempty"`
	Error          string                      `json:"error,omitempty"`
}
