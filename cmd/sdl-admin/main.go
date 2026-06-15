package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
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
	Filter       string   `json:"filter,omitempty"`
	Group        string   `json:"group,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	All          bool     `json:"all,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
	TimeoutSec   int64    `json:"timeout_sec,omitempty"`
	DurationSec  int64    `json:"duration_sec,omitempty"`
}

type adminResponse struct {
	OK             bool            `json:"ok"`
	UserID         string          `json:"user_id,omitempty"`
	Name           string          `json:"name,omitempty"`
	Domain         string          `json:"domain,omitempty"`
	Ticket         string          `json:"ticket,omitempty"`
	ExpireAtUnix   int64           `json:"expire_at_unix,omitempty"`
	Gateways       []gatewayInfo   `json:"gateways,omitempty"`
	Users          []userInfo      `json:"users,omitempty"`
	Devices        []deviceInfo    `json:"devices,omitempty"`
	UpdatedDevices []deviceInfo    `json:"updated_devices,omitempty"`
	Domains        []string        `json:"domains,omitempty"`
	DNSSnapshot    any             `json:"dns_snapshot,omitempty"`
	DebugResult    json.RawMessage `json:"debug_result,omitempty"`
	DebugPath      string          `json:"debug_path,omitempty"`
	DebugWatchID   uint64          `json:"debug_watch_id,omitempty"`
	UpdatedCount   int             `json:"updated_count,omitempty"`
	Error          string          `json:"error,omitempty"`
}

type gatewayInfo struct {
	GatewayID     string   `json:"gateway_id"`
	Endpoint      string   `json:"endpoint"`
	Approved      bool     `json:"approved"`
	Default       bool     `json:"default"`
	Reported      bool     `json:"reported"`
	Alive         bool     `json:"alive"`
	Capabilities  []string `json:"capabilities,omitempty"`
	UpdatedAtUnix int64    `json:"updated_at_unix,omitempty"`
}

type userInfo struct {
	UserID        string `json:"user_id"`
	Group         string `json:"group"`
	Domain        string `json:"domain"`
	CreatedAtUnix int64  `json:"created_at_unix,omitempty"`
}

type deviceInfo struct {
	UserID             string `json:"user_id"`
	Group              string `json:"group"`
	Name               string `json:"name"`
	DeviceID           string `json:"device_id"`
	VirtualIP          string `json:"virtual_ip"`
	ControlOnline      bool   `json:"control_online"`
	DataPlaneReachable bool   `json:"data_plane_reachable"`
	AuthedAtUnix       int64  `json:"authed_at_unix,omitempty"`
	AuthExpireAtUnix   int64  `json:"auth_expire_at_unix,omitempty"`
	AuthExpired        bool   `json:"auth_expired,omitempty"`
	UpdatedAtUnix      int64  `json:"updated_at_unix,omitempty"`
}

func main() {
	global := flag.NewFlagSet("sdl-admin", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	socket := global.String("socket", defaultSocketPath(), "admin unix socket path")
	jsonOutput := global.Bool("json", false, "print raw response as JSON")
	if err := global.Parse(os.Args[1:]); err != nil {
		fatalUsage()
	}
	args := global.Args()
	if len(args) == 0 {
		fatalUsage()
	}

	var req adminRequest
	switch args[0] {
	case "user":
		req = parseUser(args[1:])
	case "issueDeviceTicket", "issue_device_ticket":
		req = parseIssueDeviceTicket(args[1:])
	case "gateway":
		req = parseGateway(args[1:])
	case "listDevice", "list_device":
		req = parseListDevice(args[1:])
	case "extendDeviceExpiry", "extend_device_expiry":
		req = parseExtendDeviceExpiry(args[1:])
	case "approveDeviceRename", "approve_device_rename":
		req = parseApproveDeviceRename(args[1:])
	case "renameDevice", "rename_device":
		req = parseRenameDevice(args[1:])
	case "dnsDomains", "dns_domains":
		req = parseDNSDomains(args[1:])
	case "dnsSnapshot", "dns_snapshot":
		req = parseDNSSnapshot(args[1:])
	case "collectDebug", "collect_debug":
		req = parseCollectDebug(args[1:])
	case "startDebugWatch", "start_debug_watch":
		req = parseStartDebugWatch(args[1:])
	case "stopDebugWatch", "stop_debug_watch":
		req = parseStopDebugWatch(args[1:])
	default:
		fatalUsage()
	}

	resp := call(*socket, req)
	if *jsonOutput {
		if err := writeJSON(os.Stdout, resp); err != nil {
			fmt.Fprintf(os.Stderr, "encode response failed: %v\n", err)
			os.Exit(1)
		}
		if !resp.OK {
			os.Exit(1)
		}
		return
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "admin error: %s\n", resp.Error)
		os.Exit(1)
	}
	if err := writeResponse(os.Stdout, os.Stderr, req.Action, resp); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func writeResponse(stdout, stderr io.Writer, action string, resp adminResponse) error {
	switch action {
	case "create_user":
		writeKeyValueBlock(stdout, "Created user", []kv{
			{Key: "User ID", Value: valueOrDash(resp.UserID)},
			{Key: "Name", Value: valueOrDash(resp.Name)},
			{Key: "Domain", Value: valueOrDash(resp.Domain)},
		})
	case "list_users":
		writeUserTable(stdout, resp.Users)
	case "issue_device_ticket":
		writeKeyValueBlock(stdout, "Issued device ticket", []kv{
			{Key: "Ticket", Value: valueOrDash(resp.Ticket)},
			{Key: "Expires At", Value: formatUnix(resp.ExpireAtUnix)},
			{Key: "Expire Unix", Value: formatInt64(resp.ExpireAtUnix)},
		})
	case "gateway_enlist":
		writeKeyValueBlock(stdout, "Gateway enlisted", nil)
	case "gateway_delist":
		writeKeyValueBlock(stdout, "Gateway delisted", nil)
	case "gateway_list":
		writeGatewayTable(stdout, resp.Gateways)
	case "list_device":
		writeDeviceTable(stdout, "Devices", resp.Devices)
	case "extend_device_expiry":
		writeKeyValueBlock(stdout, "Extended device expiry", []kv{
			{Key: "Updated Count", Value: fmt.Sprintf("%d", resp.UpdatedCount)},
		})
		if len(resp.UpdatedDevices) > 0 {
			fmt.Fprintln(stdout)
			writeDeviceTable(stdout, "Updated devices", resp.UpdatedDevices)
		}
		if len(resp.Devices) > 0 {
			fmt.Fprintln(stdout)
			writeDeviceTable(stdout, "Current devices", resp.Devices)
		}
	case "approve_device_rename":
		writeKeyValueBlock(stdout, "Approved device rename", []kv{{Key: "Name", Value: valueOrDash(resp.Name)}})
	case "rename_device":
		writeKeyValueBlock(stdout, "Renamed device", []kv{{Key: "Name", Value: valueOrDash(resp.Name)}})
	case "dns_domains":
		writeDomains(stdout, resp.Domains)
	case "dns_snapshot":
		if err := writeJSON(stdout, resp.DNSSnapshot); err != nil {
			return fmt.Errorf("encode dns snapshot failed: %w", err)
		}
	case "collect_debug":
		if strings.TrimSpace(resp.DebugPath) != "" {
			writeKeyValueBlock(stderr, "Saved debug snapshot", []kv{{Key: "Path", Value: resp.DebugPath}})
		}
		if err := writeJSON(stdout, resp.DebugResult); err != nil {
			return fmt.Errorf("encode debug result failed: %w", err)
		}
	case "start_debug_watch":
		writeKeyValueBlock(stdout, "Started debug watch", []kv{
			{Key: "Watch ID", Value: formatUint64(resp.DebugWatchID)},
			{Key: "Path", Value: valueOrDash(resp.DebugPath)},
		})
	case "stop_debug_watch":
		writeKeyValueBlock(stdout, "Stopped debug watch", []kv{
			{Key: "Watch ID", Value: formatUint64(resp.DebugWatchID)},
			{Key: "Path", Value: valueOrDash(resp.DebugPath)},
		})
	}
	return nil
}

func parseUser(args []string) adminRequest {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var create bool
	var list bool
	var userID string
	var group string
	var filter string
	fs.BoolVar(&create, "create", false, "create a user")
	fs.BoolVar(&list, "list", false, "list users")
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "default", "default group name")
	fs.StringVar(&group, "g", "default", "default group name")
	fs.StringVar(&filter, "filter", "", "user id wildcard filter")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if fs.NArg() != 0 || create == list {
		fatalUsage()
	}
	if list {
		if strings.TrimSpace(userID) != "" || strings.TrimSpace(group) != "default" {
			fatalUsage()
		}
		return adminRequest{Action: "list_users", Filter: strings.TrimSpace(filter)}
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(filter) != "" {
		fatalUsage()
	}
	return adminRequest{
		Action: "create_user",
		UserID: strings.TrimSpace(userID),
		Group:  strings.TrimSpace(group),
	}
}

func parseIssueDeviceTicket(args []string) adminRequest {
	fs := flag.NewFlagSet("issueDeviceTicket", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	var group string
	var ttlSeconds int64
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "default.ms.net", "group name")
	fs.StringVar(&group, "g", "default.ms.net", "group name")
	fs.Int64Var(&ttlSeconds, "ttlSeconds", 300, "ticket ttl seconds")
	fs.Int64Var(&ttlSeconds, "t", 300, "ticket ttl seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "issue_device_ticket",
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		TTLSeconds: ttlSeconds,
	}
}

func parseListDevice(args []string) adminRequest {
	fs := flag.NewFlagSet("listDevice", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{Action: "list_device", UserID: strings.TrimSpace(userID)}
}

func parseExtendDeviceExpiry(args []string) adminRequest {
	fs := flag.NewFlagSet("extendDeviceExpiry", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	var group string
	var deviceID string
	var all bool
	var ttlSeconds int64
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	fs.BoolVar(&all, "all", false, "extend all devices under the user")
	fs.Int64Var(&ttlSeconds, "ttlSeconds", int64((30 * 24 * time.Hour).Seconds()), "seconds to extend")
	fs.Int64Var(&ttlSeconds, "t", int64((30 * 24 * time.Hour).Seconds()), "seconds to extend")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	if all == (strings.TrimSpace(deviceID) != "") {
		fatalUsage()
	}
	return adminRequest{
		Action:     "extend_device_expiry",
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		DeviceID:   strings.TrimSpace(deviceID),
		All:        all,
		TTLSeconds: ttlSeconds,
	}
}

func parseGateway(args []string) adminRequest {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var list bool
	var gatewayID string
	var delistGatewayID string
	fs.BoolVar(&list, "list", false, "list gateways")
	fs.StringVar(&gatewayID, "enlist", "", "approve a reported gateway id")
	fs.StringVar(&delistGatewayID, "delist", "", "remove an approved gateway id")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if fs.NArg() != 0 {
		fatalUsage()
	}
	ops := 0
	if list {
		ops++
	}
	if strings.TrimSpace(gatewayID) != "" {
		ops++
	}
	if strings.TrimSpace(delistGatewayID) != "" {
		ops++
	}
	if ops != 1 {
		fatalUsage()
	}
	if list {
		return adminRequest{Action: "gateway_list"}
	}
	if strings.TrimSpace(gatewayID) != "" {
		return adminRequest{
			Action:    "gateway_enlist",
			GatewayID: strings.TrimSpace(gatewayID),
		}
	}
	return adminRequest{
		Action:    "gateway_delist",
		GatewayID: strings.TrimSpace(delistGatewayID),
	}
}

func parseApproveDeviceRename(args []string) adminRequest {
	fs := flag.NewFlagSet("approveDeviceRename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID, group, deviceID string
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(deviceID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:   "approve_device_rename",
		UserID:   strings.TrimSpace(userID),
		Group:    strings.TrimSpace(group),
		DeviceID: strings.TrimSpace(deviceID),
	}
}

func parseRenameDevice(args []string) adminRequest {
	fs := flag.NewFlagSet("renameDevice", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID, group, deviceID, name string
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	fs.StringVar(&name, "name", "", "new device name")
	fs.StringVar(&name, "n", "", "new device name")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(deviceID) == "" || strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:   "rename_device",
		UserID:   strings.TrimSpace(userID),
		Group:    strings.TrimSpace(group),
		DeviceID: strings.TrimSpace(deviceID),
		Name:     strings.TrimSpace(name),
	}
}

func parseDNSSnapshot(args []string) adminRequest {
	fs := flag.NewFlagSet("dnsSnapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var domain string
	var group string
	fs.StringVar(&domain, "domain", "", "dns domain")
	fs.StringVar(&domain, "d", "", "dns domain")
	fs.StringVar(&group, "group", "", "optional short group name")
	fs.StringVar(&group, "g", "", "optional short group name")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(domain) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action: "dns_snapshot",
		Domain: strings.TrimSpace(domain),
		Group:  strings.TrimSpace(group),
	}
}

func parseDNSDomains(args []string) adminRequest {
	fs := flag.NewFlagSet("dnsDomains", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{Action: "dns_domains"}
}

func parseCollectDebug(args []string) adminRequest {
	fs := flag.NewFlagSet("collectDebug", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name string
	var userID string
	var group string
	var sections string
	var timeoutSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&sections, "sections", "", "comma-separated sections (runtime,gateway,peers,routes,nat,traffic)")
	fs.StringVar(&sections, "s", "", "comma-separated sections")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "collection timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "collection timeout seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "collect_debug",
		Name:       strings.TrimSpace(name),
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		Sections:   splitCSV(sections),
		TimeoutSec: timeoutSec,
	}
}

func parseStartDebugWatch(args []string) adminRequest {
	fs := flag.NewFlagSet("startDebugWatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name, userID, group, sections string
	var timeoutSec, durationSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&sections, "sections", "", "comma-separated sections (all,gateway,icmp,punch,route,runtime)")
	fs.StringVar(&sections, "s", "", "comma-separated sections")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "start timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "start timeout seconds")
	fs.Int64Var(&durationSec, "durationSec", 300, "watch duration seconds")
	fs.Int64Var(&durationSec, "d", 300, "watch duration seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:      "start_debug_watch",
		Name:        strings.TrimSpace(name),
		UserID:      strings.TrimSpace(userID),
		Group:       strings.TrimSpace(group),
		Sections:    splitCSV(sections),
		TimeoutSec:  timeoutSec,
		DurationSec: durationSec,
	}
}

func parseStopDebugWatch(args []string) adminRequest {
	fs := flag.NewFlagSet("stopDebugWatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name, userID, group string
	var timeoutSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "stop timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "stop timeout seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "stop_debug_watch",
		Name:       strings.TrimSpace(name),
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		TimeoutSec: timeoutSec,
	}
}

func call(socket string, req adminRequest) adminResponse {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect admin socket failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "send request failed: %v\n", err)
		os.Exit(1)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "read response failed: %v\n", err)
		os.Exit(1)
	}
	var resp adminResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "invalid response: %v\n", err)
		os.Exit(1)
	}
	return resp
}

func fatalUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] user --create --userId/-u user1 [--group/-g sales.ms.net]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] user --list [--filter 'user-*']")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] issueDeviceTicket --userId/-u u-1 [--group/-g default.ms.net] [--ttlSeconds/-t 300]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] gateway --list")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] listDevice --userId/-u u-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] extendDeviceExpiry --userId/-u u-1 (--deviceId/-d dev-1 | --all) [--group/-g sales.ms.net] [--ttlSeconds/-t 2592000]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] approveDeviceRename --deviceId/-d dev-1 [--group/-g sales.ms.net] [--userId/-u u-1]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] renameDevice --deviceId/-d dev-1 --name/-n new-name [--group/-g sales.ms.net] [--userId/-u u-1]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] gateway --enlist gw-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] gateway --delist gw-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] dnsDomains")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] dnsSnapshot --domain/-d ms.net [--group/-g default]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] collectDebug --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s runtime,gateway,peers,routes,nat,traffic] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] startDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s all,gateway,icmp,punch,route,runtime] [--durationSec/-d 300] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] stopDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--timeoutSec/-t 10]")
	os.Exit(2)
}

func splitCSV(v string) []string {
	items := strings.Split(v, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := strings.TrimSpace(item)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func defaultSocketPath() string {
	if v := os.Getenv("SDL_ADMIN_SOCKET"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/tmp/sdl-control-admin.sock"
}

type kv struct {
	Key   string
	Value string
}

func writeKeyValueBlock(w io.Writer, title string, pairs []kv) {
	style := newOutputStyle(w)
	fmt.Fprintln(w, style.title(title))
	for _, pair := range pairs {
		fmt.Fprintf(w, "  %-12s %s\n", style.label(pair.Key+":"), pair.Value)
	}
}

func writeGatewayTable(w io.Writer, gateways []gatewayInfo) {
	style := newOutputStyle(w)
	fmt.Fprintln(w, style.title(fmt.Sprintf("Gateways (%d)", len(gateways))))
	if len(gateways) == 0 {
		fmt.Fprintln(w, style.muted("  (none)"))
		return
	}
	headers := []string{"ID", "ENDPOINT", "DEFAULT", "APPROVED", "REPORTED", "ALIVE", "CAPABILITIES", "UPDATED AT"}
	rows := make([][]tableCell, 0, len(gateways))
	for _, gw := range gateways {
		rows = append(rows, []tableCell{
			plainCell(valueOrDash(gw.GatewayID)),
			plainCell(valueOrDash(gw.Endpoint)),
			style.boolCell(gw.Default),
			style.boolCell(gw.Approved),
			style.boolCell(gw.Reported),
			style.boolCell(gw.Alive),
			plainCell(formatCSV(gw.Capabilities)),
			style.timeCell(formatUnix(gw.UpdatedAtUnix)),
		})
	}
	renderTable(w, style, headers, rows)
}

func writeUserTable(w io.Writer, users []userInfo) {
	style := newOutputStyle(w)
	fmt.Fprintln(w, style.title(fmt.Sprintf("Users (%d)", len(users))))
	if len(users) == 0 {
		fmt.Fprintln(w, style.muted("  (none)"))
		return
	}
	headers := []string{"USER ID", "GROUP", "DOMAIN", "CREATED AT"}
	rows := make([][]tableCell, 0, len(users))
	for _, user := range users {
		rows = append(rows, []tableCell{
			plainCell(valueOrDash(user.UserID)),
			plainCell(valueOrDash(user.Group)),
			plainCell(valueOrDash(user.Domain)),
			style.timeCell(formatUnix(user.CreatedAtUnix)),
		})
	}
	renderTable(w, style, headers, rows)
}

func writeDeviceTable(w io.Writer, title string, devices []deviceInfo) {
	style := newOutputStyle(w)
	fmt.Fprintln(w, style.title(title))
	if len(devices) == 0 {
		fmt.Fprintln(w, style.muted("  (none)"))
		return
	}
	headers := []string{"USER ID", "GROUP", "NAME", "DEVICE ID", "VIRTUAL IP", "CONTROL", "DATA", "AUTH", "AUTH EXPIRES", "UPDATED AT"}
	rows := make([][]tableCell, 0, len(devices))
	for _, device := range devices {
		rows = append(rows, []tableCell{
			plainCell(valueOrDash(device.UserID)),
			plainCell(valueOrDash(device.Group)),
			plainCell(valueOrDash(device.Name)),
			plainCell(valueOrDash(device.DeviceID)),
			plainCell(valueOrDash(device.VirtualIP)),
			style.boolCell(device.ControlOnline),
			style.boolCell(device.DataPlaneReachable),
			style.authCell(formatAuthState(device)),
			style.timeCell(formatUnix(device.AuthExpireAtUnix)),
			style.timeCell(formatUnix(device.UpdatedAtUnix)),
		})
	}
	renderTable(w, style, headers, rows)
}

func writeDomains(w io.Writer, domains []string) {
	style := newOutputStyle(w)
	fmt.Fprintln(w, style.title(fmt.Sprintf("DNS domains (%d)", len(domains))))
	if len(domains) == 0 {
		fmt.Fprintln(w, style.muted("  (none)"))
		return
	}
	for _, domain := range domains {
		fmt.Fprintf(w, "  %s %s\n", style.accent("-"), domain)
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func formatBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func formatAuthState(device deviceInfo) string {
	if device.AuthExpired {
		return "expired"
	}
	if device.AuthExpireAtUnix > 0 {
		return "valid"
	}
	return "-"
}

func formatCSV(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

func formatUnix(v int64) string {
	if v <= 0 {
		return "-"
	}
	return time.Unix(v, 0).Local().Format(time.RFC3339)
}

func formatInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", v)
}

func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", v)
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

type outputStyle struct {
	enabled bool
}

type tableCell struct {
	raw      string
	rendered string
}

func newOutputStyle(w io.Writer) outputStyle {
	return outputStyle{enabled: isColorTerminal(w)}
}

func (s outputStyle) title(text string) string {
	return s.wrap(text, ansiBold+ansiCyan)
}

func (s outputStyle) label(text string) string {
	return s.wrap(text, ansiBold)
}

func (s outputStyle) accent(text string) string {
	return s.wrap(text, ansiCyan)
}

func (s outputStyle) muted(text string) string {
	return s.wrap(text, ansiGray)
}

func (s outputStyle) tableHeader(text string) string {
	return s.wrap(text, ansiBold+ansiBlue)
}

func (s outputStyle) boolCell(v bool) tableCell {
	if v {
		return styledCell("yes", s.wrap("yes", ansiGreen))
	}
	return styledCell("no", s.wrap("no", ansiRed))
}

func (s outputStyle) authCell(v string) tableCell {
	switch v {
	case "valid":
		return styledCell(v, s.wrap(v, ansiGreen))
	case "expired":
		return styledCell(v, s.wrap(v, ansiRed))
	case "-":
		return styledCell(v, s.wrap(v, ansiGray))
	default:
		return styledCell(v, s.wrap(v, ansiYellow))
	}
}

func (s outputStyle) timeCell(v string) tableCell {
	if v == "-" {
		return styledCell(v, s.wrap(v, ansiGray))
	}
	return styledCell(v, s.wrap(v, ansiBlue))
}

func (s outputStyle) wrap(text, code string) string {
	if !s.enabled || text == "" {
		return text
	}
	return code + text + ansiReset
}

func plainCell(text string) tableCell {
	return tableCell{raw: text, rendered: text}
}

func styledCell(raw, rendered string) tableCell {
	return tableCell{raw: raw, rendered: rendered}
}

func renderTable(w io.Writer, style outputStyle, headers []string, rows [][]tableCell) {
	if len(headers) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = utf8.RuneCountInString(header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			if n := utf8.RuneCountInString(cell.raw); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for i, header := range headers {
		text := padCell(header, widths[i], i == len(headers)-1)
		fmt.Fprint(w, style.tableHeader(text))
	}
	fmt.Fprintln(w)
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			fmt.Fprint(w, padRenderedCell(cell, widths[i], i == len(headers)-1))
		}
		fmt.Fprintln(w)
	}
}

func padRenderedCell(cell tableCell, width int, last bool) string {
	padding := width - utf8.RuneCountInString(cell.raw)
	if padding < 0 {
		padding = 0
	}
	suffix := strings.Repeat(" ", padding)
	if !last {
		suffix += "  "
	}
	return cell.rendered + suffix
}

func padCell(text string, width int, last bool) string {
	padding := width - utf8.RuneCountInString(text)
	if padding < 0 {
		padding = 0
	}
	suffix := strings.Repeat(" ", padding)
	if !last {
		suffix += "  "
	}
	return text + suffix
}

func isColorTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") != "" && os.Getenv("CLICOLOR_FORCE") != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
