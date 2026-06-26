package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"sdl-control/config"
	"sdl-control/control/store"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type Controller struct {
	nc      NetworkControl
	um      *UserManager
	gs      *JSONGatewayStore
	pgStore *store.Store
	cfg     *config.Config
	mu      sync.Mutex

	authChallengeMu sync.Mutex
	authChallenges  map[string]deviceAuthChallengeState
	handshakeCaps   map[string][]string

	gatewayMu               sync.RWMutex
	gatewayNodes            map[string]GatewayNodeInfo
	gatewayAllow            map[string]string
	gatewaySeen             map[string]GatewayNodeInfo
	gatewayNonce            map[string]map[string]int64
	gatewayGrantFingerprint string
	gatewayGrantPolicyRev   uint64
	gatewayGrantCache       map[string]cachedGatewayGrant

	debugMu                  sync.Mutex
	debugCollectSeq          uint64
	debugWatchSeq            uint64
	pendingDebugCollect      map[uint64]chan DebugCollectResult
	pendingDebugWatchStart   map[uint64]chan DebugWatchStartResult
	pendingDebugWatchStop    map[uint64]chan DebugWatchStopResult
	latestDebugCollect       map[string]DebugCollectResult
	debugStore               *DebugSnapshotStore
	activeDebugWatches       map[uint64]DebugWatchSession
	activeDebugWatchByDevice map[string]uint64
}

type GatewayNodeInfo struct {
	GatewayID    string
	Endpoint     string
	Capabilities []string
	Channels     []*pb.GatewayChannel
	UpdatedAt    time.Time
}

type cachedGatewayGrant struct {
	gatewayID       string
	nodeFingerprint string
	expireUnixMs    int64
	grant           *pb.GatewayAccessGrant
}

type gatewayGrantBuildOptions struct {
	lastSessionID      uint64
	lastSessionIDValid bool
	forceReissue       bool
	refresh            bool
	retainExisting     bool
}

type deviceAuthChallengeState struct {
	UserID         string
	GroupName      string
	DeviceID       string
	Ticket         string
	DevicePubKey   []byte
	Nonce          []byte
	ExpireAt       time.Time
	ReauthRequired bool
}

type GatewayAdminView struct {
	GatewayID     string   `json:"gateway_id"`
	Endpoint      string   `json:"endpoint"`
	Approved      bool     `json:"approved"`
	Default       bool     `json:"default"`
	Reported      bool     `json:"reported"`
	Alive         bool     `json:"alive"`
	Capabilities  []string `json:"capabilities,omitempty"`
	UpdatedAtUnix int64    `json:"updated_at_unix,omitempty"`
}

type DeviceAdminView struct {
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

const maxPunchAttemptsPerPair = 3
const gatewayNodeLease = 90 * time.Second
const deviceAuthChallengeTTL = 60 * time.Second
const gatewayReportFreshnessWindow = 2 * time.Minute
const gatewayGrantLease = 5 * time.Minute
const gatewayGrantGrace = 45 * time.Second
const defaultGatewayID = "default"
const defaultGatewayHost = "gateway.middlescale.net"

var gatewayGrantHardTTL = durationFromEnvSeconds("GATEWAY_GRANT_HARD_TTL_SECONDS", 24*time.Hour)
var gatewayGrantSoftRefreshLead = durationFromEnvSeconds("GATEWAY_GRANT_SOFT_REFRESH_LEAD_SECONDS", 10*time.Minute)

func durationFromEnvSeconds(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		log.Warnf("invalid %s=%q, using %s", name, raw, fallback)
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

type PunchSessionState string

const (
	PunchSessionScheduled PunchSessionState = "scheduled"
	PunchSessionSending   PunchSessionState = "sending"
	PunchSessionWaiting   PunchSessionState = "waiting"
	PunchSessionSuccess   PunchSessionState = "success"
	PunchSessionFailed    PunchSessionState = "failed"
	PunchSessionTimeout   PunchSessionState = "timeout"
)

type PunchSession struct {
	SessionID       uint64
	Source          uint32
	Target          uint32
	Attempt         uint32
	AttemptBudget   uint32
	DeadlineUnixMs  int64
	TriggerReason   string
	SelectionPolicy string
	State           PunchSessionState
	RequestedAt     int64
	LastReason      string
	RelayFallback   bool
	Ack             map[uint32]bool
	Results         map[uint32]*pb.PunchResult
}

type PunchRetryState struct {
	Attempt           uint32
	NextAllowedUnixMs int64
}

var supportedHandshakeCapabilities = map[string]struct{}{
	"udp_endpoint_report_v1": {},
	"punch_coord_v1":         {},
	"gateway_ticket_v1":      {},
}

const capabilityUDPEndpointReportV1 = "udp_endpoint_report_v1"

func NewController(cfg *config.Config, db *sql.DB) (*Controller, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var pgStore *store.Store
	if db != nil {
		pgStore = store.NewWithDB(db)
	}
	um, err := newUserManagerFromStore(db)
	if err != nil {
		return nil, err
	}
	gatewayAllow, gatewayStore := newGatewayApprovalStateFromStore()
	return &Controller{
		pgStore: pgStore,
		nc: NetworkControl{
			VirtualNetwork:    *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IPSessions:        *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
			CipherSessions:    *NewExpireMap[string, struct{}](24 * time.Hour),
			PunchSessions:     *NewExpireMap[string, *PunchSession](10 * time.Minute),
			PunchPairCooldown: *NewExpireMap[string, struct{}](20 * time.Second),
			PunchPairRetry:    *NewExpireMap[string, PunchRetryState](30 * time.Minute),
		},
		um:                       um,
		gs:                       gatewayStore,
		cfg:                      cfg,
		authChallenges:           make(map[string]deviceAuthChallengeState),
		handshakeCaps:            make(map[string][]string),
		gatewayNodes:             make(map[string]GatewayNodeInfo),
		gatewayAllow:             gatewayAllow,
		gatewaySeen:              make(map[string]GatewayNodeInfo),
		gatewayNonce:             make(map[string]map[string]int64),
		gatewayGrantCache:        make(map[string]cachedGatewayGrant),
		pendingDebugCollect:      make(map[uint64]chan DebugCollectResult),
		pendingDebugWatchStart:   make(map[uint64]chan DebugWatchStartResult),
		pendingDebugWatchStop:    make(map[uint64]chan DebugWatchStopResult),
		latestDebugCollect:       make(map[string]DebugCollectResult),
		debugStore:               newDebugSnapshotStore(cfg),
		activeDebugWatches:       make(map[uint64]DebugWatchSession),
		activeDebugWatchByDevice: make(map[string]uint64),
	}, nil
}

type umSnapshotStore interface {
	Load() (UMSnapshot, error)
	Save(UMSnapshot) error
}

func newUserManagerFromStore(db *sql.DB) (*UserManager, error) {
	if db != nil {
		pgStore := NewPostgresUMStore(db)
		snapshot, err := loadUMSnapshotForPostgresStore(pgStore)
		if err != nil {
			return nil, err
		}
		um := NewUserManager()
		um.store = pgStore
		um.restore(snapshot)
		return um, nil
	}
	path := os.Getenv("UM_STORE_JSON_PATH")
	if path == "" {
		path = "./data/um.json"
	}
	um, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		log.Warnf("load user manager from json failed (%s): %v; fallback to memory", path, err)
		return NewUserManager(), nil
	}
	return um, nil
}

func loadUMSnapshotForPostgresStore(store umSnapshotStore) (UMSnapshot, error) {
	snapshot, err := store.Load()
	if err != nil {
		return UMSnapshot{}, fmt.Errorf("load user manager from postgres: %w", err)
	}
	if !isEmptyUMSnapshot(snapshot) {
		return snapshot, nil
	}
	migrationPath := os.Getenv("UM_STORE_MIGRATION_JSON_PATH")
	if migrationPath == "" {
		return snapshot, nil
	}
	seedSnapshot, err := NewJSONUMStore(migrationPath).Load()
	if err != nil {
		return UMSnapshot{}, fmt.Errorf("load user manager migration snapshot (%s): %w", migrationPath, err)
	}
	if isEmptyUMSnapshot(seedSnapshot) {
		return snapshot, nil
	}
	if err := store.Save(seedSnapshot); err != nil {
		return UMSnapshot{}, fmt.Errorf("seed user manager from json (%s): %w", migrationPath, err)
	}
	log.Infof("seeded postgres user manager from %s", migrationPath)
	return seedSnapshot, nil
}

func isEmptyUMSnapshot(snapshot UMSnapshot) bool {
	return snapshot.UserSeq == 0 &&
		snapshot.EnrollmentSeq == 0 &&
		len(snapshot.Users) == 0 &&
		len(snapshot.Policies) == 0 &&
		len(snapshot.Enrollments) == 0 &&
		len(snapshot.DeviceByPubKey) == 0 &&
		len(snapshot.CertifiedDevices) == 0 &&
		len(snapshot.DeviceTickets) == 0
}

func newGatewayApprovalStateFromStore() (map[string]string, *JSONGatewayStore) {
	path := os.Getenv("GATEWAY_STORE_JSON_PATH")
	if path == "" {
		path = "./data/gateways.json"
	}
	store := NewJSONGatewayStore(path)
	snapshot, err := store.Load()
	if err != nil {
		log.Warnf("load gateway approval store failed (%s): %v; fallback to memory", path, err)
		return map[string]string{}, store
	}
	approved := make(map[string]string, len(snapshot.Approved))
	for gatewayID, endpoint := range snapshot.Approved {
		gatewayID = strings.TrimSpace(gatewayID)
		endpoint = strings.TrimSpace(endpoint)
		if gatewayID == "" || endpoint == "" {
			continue
		}
		approved[gatewayID] = endpoint
	}
	return approved, store
}

func newDebugSnapshotStore(cfg *config.Config) *DebugSnapshotStore {
	path := strings.TrimSpace(os.Getenv("DEBUG_COLLECT_DIR"))
	if path == "" && cfg != nil {
		path = strings.TrimSpace(cfg.DebugCollectDir)
	}
	if path == "" {
		path = "./data/debug-collect"
	}
	keepPerDevice := 20
	if cfg != nil && cfg.DebugCollectKeepPerDevice > 0 {
		keepPerDevice = cfg.DebugCollectKeepPerDevice
	}
	if value := strings.TrimSpace(os.Getenv("DEBUG_COLLECT_KEEP_PER_DEVICE")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			keepPerDevice = parsed
		}
	}
	return NewDebugSnapshotStore(path, keepPerDevice)
}

func (c *Controller) persistGatewayApprovalLocked() {
	snapshot := GatewayStoreSnapshot{
		Approved: make(map[string]string, len(c.gatewayAllow)),
	}
	for gatewayID, endpoint := range c.gatewayAllow {
		gatewayID = strings.TrimSpace(gatewayID)
		endpoint = strings.TrimSpace(endpoint)
		if gatewayID == "" || endpoint == "" {
			continue
		}
		snapshot.Approved[gatewayID] = endpoint
	}
	if c.gs != nil {
		if err := c.gs.Save(snapshot); err != nil {
			log.Warnf("persist gateway approval store (json) failed: %v", err)
		}
	}
}

func (c *Controller) PgStore() *store.Store {
	return c.pgStore
}

func (c *Controller) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IPSessions.Stop()
	c.nc.CipherSessions.Stop()
	c.nc.PunchSessions.Stop()
	c.nc.PunchPairCooldown.Stop()
	c.nc.PunchPairRetry.Stop()
}

func (c *Controller) HandleHandshakePacket(reqPacket *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	log.Debugf("收到客户端 HandshakeRequest Packet: %s", reqPacket.DebugString())
	var req pb.HandshakeRequest
	if err := proto.Unmarshal(reqPacket.Payload, &req); err != nil {
		log.Errorf("HandshakeRequest unmarshal error: %v", err)
		return nil, err
	}
	negotiatedCapabilities := negotiateHandshakeCapabilities(req.GetCapabilities())
	c.setPendingHandshakeCapabilities(remoteAddr, negotiatedCapabilities)

	rsp := &pb.HandshakeResponse{
		Version:      "goversion-1.0.0",
		Capabilities: negotiatedCapabilities,
	}
	playload, err := proto.Marshal(rsp)
	if err != nil {
		log.Errorf("HandshakeResponse marshal error: %v", err)
		return nil, err
	}

	rspPacket := &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoHandshakeResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     reqPacket.DstIP,
		DstIP:     reqPacket.SrcIP,
		Payload:   playload,
	}

	// 目前不处理 handshake的加密算法

	return rspPacket, nil
}

func (c *Controller) HandleRegistrationPacketWithVirtualIPAndCapabilities(
	request *protocol.Packet,
	remoteAddr net.Addr,
	negotiatedCapabilities []string,
) (*protocol.Packet, uint32, NetworkIdentity, error) {
	log.Debugf("收到客户端 RegistrationRequest Packet: %s", request.DebugString())
	var registration pb.RegistrationRequest
	if err := proto.Unmarshal(request.Payload, &registration); err != nil {
		log.Errorf("RegistrationRequest unmarshal error: %v", err)
		return nil, 0, NetworkIdentity{}, err
	}
	if err := validateRegistrationRequest(&registration); err != nil {
		log.Errorf("RegistrationRequest validate error: %v", err)
		return nil, 0, NetworkIdentity{}, err
	}

	authGroup := registration.GetToken()
	gateway, netmask, err := c.resolveGroupNetworkConfig(authGroup)
	if err != nil {
		return nil, 0, NetworkIdentity{}, err
	}
	if err := c.UMCheckAuthedDevice(authGroup, registration.GetDeviceId(), registration.GetDevicePubKey()); err != nil {
		c.clearStaleClientStateByDeviceID(authGroup, registration.GetDeviceId())
		return nil, 0, NetworkIdentity{}, fmt.Errorf("device %s auth check failed for group %s: %w", registration.GetDeviceId(), authGroup, err)
	}
	displayName := strings.TrimSpace(registration.GetName())
	authRecord, ok := c.UMGetAuthedDevice(authGroup, registration.GetDeviceId())
	if !ok {
		return nil, 0, NetworkIdentity{}, fmt.Errorf("device %s auth record missing for group %s", registration.GetDeviceId(), authGroup)
	}
	if strings.TrimSpace(authRecord.DisplayName) == "" {
		assignedRecord, err := c.UMAssignAuthedDeviceDisplayName(authGroup, registration.GetDeviceId(), displayName)
		if err != nil {
			return nil, 0, NetworkIdentity{}, err
		}
		authRecord = assignedRecord
	}
	if persisted := strings.TrimSpace(authRecord.DisplayName); persisted != "" {
		displayName = persisted
	}
	networkIdentity := NewNetworkIdentity(authGroup, authRecord.UserID)
	if !hasCapability(negotiatedCapabilities, capabilityUDPEndpointReportV1) {
		log.Warnf(
			"client %s missing handshake capability %q; allowing registration with relay-only compatibility",
			remoteAddr.String(),
			capabilityUDPEndpointReportV1,
		)
	}

	raddrStr := remoteAddr.String()
	host, portStr, err := net.SplitHostPort(raddrStr)
	if err != nil {
		return nil, 0, NetworkIdentity{}, fmt.Errorf("Failed to parse remote address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, 0, NetworkIdentity{}, fmt.Errorf("invalid remote port: %q", portStr)
	}
	pubPort := uint32(port)

	registrationResp := &pb.RegistrationResponse{
		PublicPort: pubPort,
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			registrationResp.PublicIp = util.IpToUint32(ip4)
		} else {
			registrationResp.PublicIpv6 = ip.To16()
		}
	}
	registrationResp.VirtualGateway = util.IpToUint32(gateway)
	registrationResp.VirtualNetmask = util.MaskToUint32(netmask)
	registrationResp.DnsProfile = c.BuildClientDNSProfile(authGroup)

	c.mu.Lock()
	defer c.mu.Unlock()

	netInfo, netInfoExist := c.nc.VirtualNetwork.Get(networkIdentity.Key())
	if !netInfoExist {
		netInfo = NewNetworkInfo(networkIdentity.Key(), netmask, net.IP(gateway), c.reservedServiceIPs(authGroup))
		c.nc.VirtualNetwork.Set(networkIdentity.Key(), netInfo)
	}
	virtualIP, oldIP, err := c.nc.generateIP(
		netInfo,
		registration.GetVirtualIp(),
		registration.GetDeviceId(),
		registration.GetAllowIpChange(),
	)
	if err != nil {
		return nil, 0, NetworkIdentity{}, err
	}
	if oldIP != 0 && oldIP != virtualIP {
		netInfo.DeleteClient(oldIP)
		c.nc.IPSessions.Delete(NewIpSessionKey(networkIdentity.Key(), util.Uint32ToIP(oldIP)))
	}
	clientInfo := netInfo.Clients[virtualIP]
	now := time.Now().Unix()
	clientInfo.DeviceId = registration.GetDeviceId()
	clientInfo.Name = displayName
	clientInfo.UserID = authRecord.UserID
	clientInfo.NetworkKey = networkIdentity.Key()
	clientInfo.AuthGroup = authGroup
	clientInfo.NetworkScope = networkIdentity.Scope()
	clientInfo.Version = registration.GetVersion()
	clientInfo.Capabilities = negotiatedCapabilities
	clientInfo.ControlOnline = true
	clientInfo.ControlLastSeen = now
	clientInfo.DataPlaneReachable = false
	clientInfo.DataPlaneLastSeen = 0
	clientInfo.PreferredChannelMode = pb.ChannelMode_CHANNEL_MODE_AUTO
	clientInfo.VirtualIp = virtualIP
	clientInfo.Address = remoteAddr
	clientInfo.DevicePubKey = append(clientInfo.DevicePubKey[:0], registration.GetDevicePubKey()...)
	clientInfo.OnlineKxPub = append(clientInfo.OnlineKxPub[:0], registration.GetOnlineKxPub()...)
	clientInfo.LastJoin = now
	netInfo.UpsertClient(virtualIP, clientInfo)
	c.nc.IPSessions.Delete(NewIpSessionKey(networkIdentity.Key(), util.Uint32ToIP(virtualIP)))
	c.nc.TouchCipherSession(remoteAddr)
	netInfo.Epoch++
	registrationResp.VirtualIp = virtualIP
	gatewayGrants, gatewayPolicyRev := c.buildGatewayAccessGrantsForExistingClient(networkIdentity.Key(), virtualIP, registration.GetDeviceId())
	registrationResp.GatewayAccessGrant = selectPrimaryGatewayGrant(gatewayGrants)
	registrationResp.GatewayAccessGrants = gatewayGrants
	registrationResp.GatewayPolicyRev = gatewayPolicyRev
	registrationResp.Epoch = uint32(netInfo.Epoch)
	registrationResp.DeviceInfoList = buildDeviceInfoList(netInfo.Clients, virtualIP)

	respBytes, err := proto.Marshal(registrationResp)
	if err != nil {
		return nil, 0, NetworkIdentity{}, fmt.Errorf("RegistrationResponse marshal error: %v", err)
	}

	respPacket := &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRegistrationResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   respBytes,
	}

	return respPacket, virtualIP, networkIdentity, nil
}

func (c *Controller) HandleDeviceRenamePacket(request *protocol.Packet) (*protocol.Packet, uint32, error) {
	var req pb.DeviceRenameRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, 0, err
	}
	deviceID := strings.TrimSpace(req.GetDeviceId())
	newName, err := normalizeRenameName(req.GetNewName())
	if err != nil {
		resp, packetErr := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    err.Error(),
		})
		return resp, 0, packetErr
	}
	if deviceID == "" {
		resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    "device_id is empty",
		})
		return resp, 0, err
	}
	srcIP := util.IpToUint32(request.SrcIP)
	groupName := ""
	c.nc.VirtualNetwork.mutex.RLock()
	for key, network := range c.nc.VirtualNetwork.data {
		if strings.TrimSpace(request.RouteNetworkKey) != "" && key != request.RouteNetworkKey {
			continue
		}
		client, ok := network.Clients[srcIP]
		if !ok {
			continue
		}
		if client.DeviceId != deviceID {
			c.nc.VirtualNetwork.mutex.RUnlock()
			resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
				RequestId: req.GetRequestId(),
				Ok:        false,
				Reason:    "device mismatch",
			})
			return resp, 0, err
		}
		if c.networkHasDuplicateDeviceNameLocked(network, deviceID, newName) {
			c.nc.VirtualNetwork.mutex.RUnlock()
			resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
				RequestId: req.GetRequestId(),
				Ok:        false,
				Reason:    "device name already exists",
			})
			return resp, 0, err
		}
		groupName = clientAuthGroup(client, network.Group)
		break
	}
	c.nc.VirtualNetwork.mutex.RUnlock()
	if groupName == "" {
		resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    "device not registered",
		})
		return resp, 0, err
	}
	if err := c.UMSetAuthedDeviceDisplayName(groupName, deviceID, newName); err != nil {
		resp, packetErr := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    err.Error(),
		})
		return resp, 0, packetErr
	}
	resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
		RequestId:   req.GetRequestId(),
		Ok:          true,
		Reason:      "restart required to apply rename",
		AppliedName: newName,
	})
	return resp, 0, err
}

func (c *Controller) networkHasDuplicateDeviceNameLocked(network *NetworkInfo, deviceID string, newName string) bool {
	newName = strings.TrimSpace(newName)
	if network == nil || newName == "" {
		return false
	}
	for _, client := range network.Clients {
		if client.DeviceId == deviceID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(client.Name), newName) {
			return true
		}
	}
	return false
}

func normalizeRenameName(newName string) (string, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return "", fmt.Errorf("name is empty")
	}
	if len(newName) > 128 {
		return "", fmt.Errorf("name too long")
	}
	return newName, nil
}

func (c *Controller) clearStaleClientStateByDeviceID(authGroup, deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().Unix()
	for _, netInfo := range c.nc.VirtualNetwork.data {
		networkChanged := false
		for virtualIP, clientInfo := range netInfo.Clients {
			if clientInfo.DeviceId != deviceID || clientAuthGroup(clientInfo, netInfo.Group) != authGroup {
				continue
			}
			if !clientInfo.ControlOnline && clientInfo.ClientStatus == nil && !clientInfo.DataPlaneReachable {
				continue
			}
			clientInfo.ControlOnline = false
			clientInfo.ControlLastSeen = now
			clientInfo.DataPlaneReachable = false
			clientInfo.DataPlaneLastSeen = 0
			clientInfo.ClientStatus = nil
			clientInfo.PreferredChannelMode = pb.ChannelMode_CHANNEL_MODE_AUTO
			netInfo.UpsertClient(virtualIP, clientInfo)
			c.nc.IPSessions.Set(NewIpSessionKey(netInfo.Group, util.Uint32ToIP(virtualIP)), clientInfo.Address)
			networkChanged = true
		}
		if networkChanged {
			netInfo.Epoch++
		}
	}
}

func (c *Controller) removeAuthedDeviceRuntimeState(records []UMAuthDevice) {
	if len(records) == 0 {
		return
	}
	remove := make(map[string]struct{}, len(records))
	for _, record := range records {
		remove[authedDeviceKey(record.GroupName, record.DeviceID)] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for networkKey, netInfo := range c.nc.VirtualNetwork.data {
		networkChanged := false
		for virtualIP, clientInfo := range netInfo.Clients {
			authGroup := clientAuthGroup(clientInfo, netInfo.Group)
			if _, ok := remove[authedDeviceKey(authGroup, clientInfo.DeviceId)]; !ok {
				continue
			}
			netInfo.DeleteClient(virtualIP)
			c.nc.IPSessions.Delete(NewIpSessionKey(networkKey, util.Uint32ToIP(virtualIP)))
			networkChanged = true
		}
		if networkChanged {
			netInfo.Epoch++
		}
	}
}

func (c *Controller) updateAuthedDeviceRuntimeName(record UMAuthDevice) {
	displayName := strings.TrimSpace(record.DisplayName)
	if displayName == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, netInfo := range c.nc.VirtualNetwork.data {
		networkChanged := false
		for virtualIP, clientInfo := range netInfo.Clients {
			authGroup := clientAuthGroup(clientInfo, netInfo.Group)
			if authGroup != record.GroupName || clientInfo.DeviceId != record.DeviceID {
				continue
			}
			if clientInfo.Name == displayName {
				continue
			}
			clientInfo.Name = displayName
			netInfo.UpsertClient(virtualIP, clientInfo)
			networkChanged = true
		}
		if networkChanged {
			netInfo.Epoch++
		}
	}
}

func (c *Controller) BuildRegistrationErrorPacket(request *protocol.Packet, err error) (*protocol.Packet, error) {
	code, errorReason, reason := classifyRegistrationError(err)
	resp := &pb.RegistrationResponse{
		ErrorCode:    code,
		ErrorMessage: reason,
		ErrorReason:  errorReason,
	}
	payload, marshalErr := proto.Marshal(resp)
	if marshalErr != nil {
		return nil, fmt.Errorf("RegistrationResponse(error) marshal error: %v", marshalErr)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRegistrationResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func classifyRegistrationError(err error) (uint32, pb.RegistrationErrorReason, string) {
	code := uint32(1)
	errorReason := pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_INTERNAL
	reason := "registration failed"
	if err == nil {
		return code, errorReason, reason
	}
	reason = err.Error()
	switch {
	case strings.Contains(reason, "expect <group>.<domain>"),
		strings.Contains(reason, "not configured in domains"):
		code = 1001
		errorReason = pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_INVALID_GROUP_DOMAIN
	case strings.Contains(reason, "not authed"):
		code = 1002
		errorReason = pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_NOT_AUTHED
	case strings.Contains(reason, "unmarshal"),
		strings.Contains(reason, "validate"):
		code = 1003
		errorReason = pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_INVALID_REQUEST
	case strings.Contains(reason, "missing required handshake capability"):
		code = 1004
		errorReason = pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY
	default:
		code = 1999
		errorReason = pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_INTERNAL
	}
	return code, errorReason, reason
}

func (c *Controller) HandlePullDeviceListPacket(request *protocol.Packet) (*protocol.Packet, error) {
	return c.HandlePullDeviceListPacketInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) HandlePullDeviceListPacketInNetwork(request *protocol.Packet, networkKey string) (*protocol.Packet, error) {
	selfIP := util.IpToUint32(request.SrcIP)
	deviceList, ok := c.nc.DeviceListByIPInNetwork(networkKey, selfIP)
	if !ok {
		return c.buildDisconnectPacket(request), nil
	}
	if client, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, selfIP); ok {
		routeNetworkKey := networkKey
		if strings.TrimSpace(routeNetworkKey) == "" {
			routeNetworkKey = clientNetworkKey(client, "")
		}
		deviceList.GatewayAccessGrants, deviceList.GatewayPolicyRev = c.buildGatewayAccessGrantsForExistingClient(routeNetworkKey, selfIP, client.DeviceId)
	}
	payload, err := proto.Marshal(deviceList)
	if err != nil {
		return nil, fmt.Errorf("DeviceList marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPushDeviceList,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) BuildPushDeviceListPacketsForPeerChange(changedIP uint32) ([]*protocol.Packet, error) {
	return c.BuildPushDeviceListPacketsForPeerChangeInNetwork("", changedIP)
}

func (c *Controller) BuildPushDeviceListPacketsForPeerChangeInNetwork(networkKey string, changedIP uint32) ([]*protocol.Packet, error) {
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()

	for key, network := range c.nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		changedClient, ok := network.Clients[changedIP]
		if !ok {
			continue
		}
		if !changedClient.ControlOnline {
			return nil, nil
		}
		changedScope := clientNetworkScope(changedClient, network.Group)
		packets := make([]*protocol.Packet, 0, len(network.Clients))
		for targetIP, targetClient := range network.Clients {
			if targetIP == changedIP || !targetClient.ControlOnline {
				continue
			}
			if clientNetworkScope(targetClient, network.Group) != changedScope {
				continue
			}
			targetNetworkKey := clientNetworkKey(targetClient, network.Group)
			gatewayGrants, gatewayPolicyRev := c.buildGatewayAccessGrantsForExistingClient(targetNetworkKey, targetIP, targetClient.DeviceId)
			packet, err := c.buildPushDeviceListPacket(
				targetNetworkKey,
				targetIP,
				uint32(network.Epoch),
				buildDeviceInfoList(network.Clients, targetIP),
				gatewayGrants,
				gatewayPolicyRev,
			)
			if err != nil {
				return nil, err
			}
			packets = append(packets, packet)
		}
		return packets, nil
	}
	return nil, nil
}

func (c *Controller) BuildPushDeviceListPacketsForGatewayChange() ([]*protocol.Packet, error) {
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()

	var packets []*protocol.Packet
	for _, network := range c.nc.VirtualNetwork.data {
		for targetIP, targetClient := range network.Clients {
			if !targetClient.ControlOnline {
				continue
			}
			targetNetworkKey := clientNetworkKey(targetClient, network.Group)
			gatewayGrants, gatewayPolicyRev := c.buildGatewayAccessGrantsForExistingClient(targetNetworkKey, targetIP, targetClient.DeviceId)
			packet, err := c.buildPushDeviceListPacket(
				targetNetworkKey,
				targetIP,
				uint32(network.Epoch),
				buildDeviceInfoList(network.Clients, targetIP),
				gatewayGrants,
				gatewayPolicyRev,
			)
			if err != nil {
				return nil, err
			}
			packets = append(packets, packet)
		}
	}
	return packets, nil
}

func (c *Controller) BuildPushDeviceListPacketsForGatewayChangeIfNeeded() ([]*protocol.Packet, error) {
	c.gatewayMu.Lock()
	_, changed := c.syncGatewayGrantPolicyLocked(c.approvedAliveGatewayNodesLocked(time.Now()))
	c.gatewayMu.Unlock()
	if !changed {
		return nil, nil
	}
	return c.BuildPushDeviceListPacketsForGatewayChange()
}

func (c *Controller) buildPushDeviceListPacket(
	networkKey string,
	targetIP uint32,
	epoch uint32,
	deviceInfoList []*pb.DeviceInfo,
	gatewayGrants []*pb.GatewayAccessGrant,
	gatewayPolicyRev uint64,
) (*protocol.Packet, error) {
	push := &pb.DeviceList{
		Epoch:               epoch,
		DeviceInfoList:      deviceInfoList,
		GatewayAccessGrants: gatewayGrants,
		GatewayPolicyRev:    gatewayPolicyRev,
	}
	payload, err := proto.Marshal(push)
	if err != nil {
		return nil, fmt.Errorf("DeviceList marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:             protocol.V3,
		Proto:           protocol.ProtocolService,
		AppProto:        protocol.AppProtoPushDeviceList,
		SourceTTL:       protocol.MAX_TTL,
		TTL:             protocol.MAX_TTL,
		SrcIP:           net.ParseIP("0.0.0.1"),
		DstIP:           util.Uint32ToIP(targetIP),
		Payload:         payload,
		RouteNetworkKey: networkKey,
	}, nil
}

func (c *Controller) buildDisconnectPacket(request *protocol.Packet) *protocol.Packet {
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolError,
		AppProto:  protocol.AppProtocol(2),
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
	}
}

func (c *Controller) HandleDeviceAuthPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.DeviceAuthRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	groupName, err := c.UMValidateDeviceAuth(req.GetUserId(), req.GetGroup(), req.GetDeviceId(), req.GetTicket())
	if err != nil {
		ack := &pb.DeviceAuthAck{
			Ok:       false,
			Reason:   err.Error(),
			UserId:   req.GetUserId(),
			Group:    req.GetGroup(),
			DeviceId: req.GetDeviceId(),
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if len(req.GetDevicePubKey()) == 0 {
		ack := &pb.DeviceAuthAck{
			Ok:       false,
			Reason:   "device public key is empty",
			UserId:   req.GetUserId(),
			Group:    req.GetGroup(),
			DeviceId: req.GetDeviceId(),
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	reauthRequired := false
	if existing, ok := c.UMGetAuthedDevice(groupName, req.GetDeviceId()); ok {
		if existing.PubKeyHex != toPubKeyHex(req.GetDevicePubKey(), "ed25519") {
			reauthRequired = true
		}
	}
	challenge, err := c.newDeviceAuthChallenge(req.GetUserId(), groupName, req.GetDeviceId(), req.GetTicket(), req.GetDevicePubKey(), reauthRequired)
	if err != nil {
		return nil, err
	}
	return c.buildServicePacket(request, protocol.AppProtoDeviceAuthChallenge, challenge)
}

func (c *Controller) HandleDeviceAuthProofPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.DeviceAuthProof
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	challenge, ok := c.consumeDeviceAuthChallenge(req.GetChallengeId())
	if !ok || time.Now().After(challenge.ExpireAt) {
		ack := &pb.DeviceAuthAck{
			Ok:          false,
			Reason:      "challenge_expired",
			DeviceId:    req.GetDeviceId(),
			ErrorReason: pb.DeviceAuthErrorReason_DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if challenge.DeviceID != req.GetDeviceId() || !bytes.Equal(challenge.DevicePubKey, req.GetDevicePubKey()) {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         "device_key_mismatch",
			DeviceId:       req.GetDeviceId(),
			ReauthRequired: challenge.ReauthRequired,
			ErrorReason:    pb.DeviceAuthErrorReason_DEVICE_AUTH_ERROR_REASON_DEVICE_KEY_MISMATCH,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if !ed25519.Verify(ed25519.PublicKey(req.GetDevicePubKey()), buildDeviceAuthSignedPayload(req.GetChallengeId(), challenge.Nonce, req.GetDeviceId(), req.GetDevicePubKey()), req.GetSignature()) {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         "invalid_signature",
			DeviceId:       req.GetDeviceId(),
			ReauthRequired: challenge.ReauthRequired,
			ErrorReason:    pb.DeviceAuthErrorReason_DEVICE_AUTH_ERROR_REASON_INVALID_SIGNATURE,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	record, err := c.UMAuthDevice(challenge.UserID, challenge.GroupName, challenge.DeviceID, challenge.Ticket, challenge.DevicePubKey)
	if err != nil {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         err.Error(),
			UserId:         challenge.UserID,
			Group:          challenge.GroupName,
			DeviceId:       challenge.DeviceID,
			ReauthRequired: challenge.ReauthRequired,
			ErrorReason:    pb.DeviceAuthErrorReason_DEVICE_AUTH_ERROR_REASON_AUTH_CHECK_FAILED,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	ack := &pb.DeviceAuthAck{
		Ok:               true,
		UserId:           record.UserID,
		Group:            record.GroupName,
		DeviceId:         record.DeviceID,
		AuthExpireUnixMs: record.AuthExpireAt.UnixMilli(),
		ReauthRequired:   challenge.ReauthRequired,
	}
	return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
}

func (c *Controller) HandleRefreshGatewayGrantPacket(request *protocol.Packet) (*protocol.Packet, error) {
	return c.HandleRefreshGatewayGrantPacketInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) HandleRefreshGatewayGrantPacketInNetwork(request *protocol.Packet, networkKey string) (*protocol.Packet, error) {
	var req pb.RefreshGatewayGrantRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	if req.GetVirtualIp() == 0 {
		return nil, fmt.Errorf("refresh gateway grant virtual_ip is empty")
	}
	if req.GetDeviceId() == "" {
		return nil, fmt.Errorf("refresh gateway grant device_id is empty")
	}
	if srcIP := request.SrcIP.To4(); srcIP == nil || util.IpToUint32(srcIP) != req.GetVirtualIp() {
		return nil, fmt.Errorf("refresh gateway grant source mismatch")
	}
	if !c.clientOwnsVirtualIPInNetwork(networkKey, req.GetVirtualIp(), req.GetDeviceId()) {
		return nil, fmt.Errorf("refresh gateway grant device mismatch")
	}
	if strings.TrimSpace(networkKey) == "" {
		if client, ok := c.nc.FindClientByVirtualIP(req.GetVirtualIp()); ok {
			networkKey = clientNetworkKey(client, "")
		}
	}

	resp := &pb.RefreshGatewayGrantResponse{
		HasUpdate: true,
		Reason:    "refreshed",
		Result:    pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_UPDATED,
	}
	grants, gatewayPolicyRev, changed := c.buildGatewayAccessGrantsForRefresh(
		networkKey,
		req.GetVirtualIp(),
		req.GetDeviceId(),
		req.GetLastSessionId(),
		req.GetForceReissue(),
	)
	if len(grants) > 0 {
		resp.GatewayPolicyRev = gatewayPolicyRev
		if !req.GetForceReissue() &&
			req.GetLastSessionId() != 0 &&
			req.GetLastPolicyRev() == gatewayPolicyRev &&
			!changed {
			resp.HasUpdate = false
			resp.Reason = "gateway grant unchanged"
			resp.Result = pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE
		} else {
			resp.GatewayAccessGrant = selectPrimaryGatewayGrant(grants)
			resp.GatewayAccessGrants = grants
		}
	} else if req.GetLastPolicyRev() < gatewayPolicyRev {
		resp.Reason = "gateway policy cleared"
		resp.GatewayPolicyRev = gatewayPolicyRev
		resp.Result = pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_REVOKED
	} else {
		resp.HasUpdate = false
		resp.Reason = "no gateway available"
		resp.GatewayPolicyRev = gatewayPolicyRev
		resp.Result = pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_TEMPORARILY_UNAVAILABLE
	}
	payload, err := proto.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) HandleClientStatusInfoPacket(request *protocol.Packet) (bool, error) {
	return c.HandleClientStatusInfoPacketInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) HandleClientStatusInfoPacketInNetwork(request *protocol.Packet, networkKey string) (bool, error) {
	var status pb.ClientStatusInfo
	if err := proto.Unmarshal(request.Payload, &status); err != nil {
		return false, fmt.Errorf("ClientStatusInfo unmarshal error: %v", err)
	}
	srcIP := util.IpToUint32(request.SrcIP)
	if status.GetSource() != 0 && status.GetSource() != srcIP {
		return false, fmt.Errorf("client status source mismatch: %d != %d", status.GetSource(), srcIP)
	}
	now := time.Now().Unix()
	clientStatus := &ClientStatusInfo{
		P2PList:            make([]net.IP, 0, len(status.GetP2PList())),
		PublicUDPEndpoints: make([]*net.UDPAddr, 0, len(status.GetPublicUdpEndpoints())),
		LocalUDPEndpoints:  make([]*net.UDPAddr, 0, len(status.GetLocalUdpEndpoints())),
		UpStream:           status.GetUpStream(),
		DownStream:         status.GetDownStream(),
		IsCone:             status.GetNatType() == pb.PunchNatType_Cone,
		PunchTriggerReason: status.GetPunchTriggerReason().String(),
		UpdateTime:         now,
	}
	for _, item := range status.GetP2PList() {
		clientStatus.P2PList = append(clientStatus.P2PList, util.Uint32ToIP(item.GetNextIp()))
	}
	for _, endpoint := range status.GetPublicUdpEndpoints() {
		if endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 {
			continue
		}
		var ip net.IP
		if endpoint.GetIp() != 0 {
			ip = util.Uint32ToIP(endpoint.GetIp())
		} else if len(endpoint.GetIpv6()) == net.IPv6len {
			ip = append(net.IP(nil), endpoint.GetIpv6()...)
		}
		if ip == nil {
			continue
		}
		clientStatus.PublicUDPEndpoints = append(clientStatus.PublicUDPEndpoints, &net.UDPAddr{
			IP:   ip,
			Port: int(endpoint.GetPort()),
		})
	}
	for _, endpoint := range status.GetLocalUdpEndpoints() {
		if endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 {
			continue
		}
		var ip net.IP
		if endpoint.GetIp() != 0 {
			ip = util.Uint32ToIP(endpoint.GetIp())
		} else if len(endpoint.GetIpv6()) == net.IPv6len {
			ip = append(net.IP(nil), endpoint.GetIpv6()...)
		}
		if ip == nil {
			continue
		}
		clientStatus.LocalUDPEndpoints = append(clientStatus.LocalUDPEndpoints, &net.UDPAddr{
			IP:   ip,
			Port: int(endpoint.GetPort()),
		})
	}
	reachable := len(clientStatus.P2PList) > 0
	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()
	for key, network := range c.nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		client, ok := network.Clients[srcIP]
		if !ok {
			continue
		}
		client.ControlOnline = true
		client.ControlLastSeen = now
		client.DataPlaneReachable = reachable
		if reachable {
			client.DataPlaneLastSeen = now
		}
		changed := client.PreferredChannelMode != status.GetPreferredChannelMode()
		client.ClientStatus = clientStatus
		client.PreferredChannelMode = status.GetPreferredChannelMode()
		network.UpsertClient(srcIP, client)
		return changed, nil
	}
	return false, fmt.Errorf("client %s not registered", request.SrcIP)
}

func (c *Controller) BuildPunchStartPacketsFromStatus(request *protocol.Packet) ([]*protocol.Packet, error) {
	return c.BuildPunchStartPacketsFromStatusInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) BuildPunchStartPacketsFromStatusInNetwork(request *protocol.Packet, networkKey string) ([]*protocol.Packet, error) {
	srcIP := util.IpToUint32(request.SrcIP)
	now := time.Now()
	nowMs := now.UnixMilli()
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()
	for key, network := range c.nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		srcClient, ok := network.Clients[srcIP]
		if !ok || !srcClient.ControlOnline || srcClient.ClientStatus == nil {
			continue
		}
		for targetIP, targetClient := range network.Clients {
			if targetIP == srcIP || !targetClient.ControlOnline || targetClient.ClientStatus == nil {
				continue
			}
			triggerReason := pb.PunchTriggerReason_PunchTriggerStatusUpdate
			if srcClient.ClientStatus != nil {
				if parsed, ok := pb.PunchTriggerReason_value[srcClient.ClientStatus.PunchTriggerReason]; ok {
					triggerReason = pb.PunchTriggerReason(parsed)
				}
			}
			if triggerReason == pb.PunchTriggerReason_PunchTriggerStatusUpdate {
				if shouldSuppressPunchStartForStatusUpdate(srcClient, srcIP, targetClient, targetIP) {
					continue
				}
			} else if shouldSuppressPunchStartForOtherTrigger(srcClient, srcIP, targetClient, targetIP) {
				continue
			}
			manualTrigger := triggerReason == pb.PunchTriggerReason_PunchTriggerManualRequest
			pairKey := punchPairKey(srcIP, targetIP)
			if !manualTrigger {
				if _, cooling := c.nc.PunchPairCooldown.Get(pairKey); cooling {
					continue
				}
			}
			retryState, hasRetry := c.nc.PunchPairRetry.Get(pairKey)
			if manualTrigger {
				hasRetry = false
				c.nc.PunchPairRetry.Delete(pairKey)
			} else if hasRetry {
				if retryState.Attempt >= maxPunchAttemptsPerPair {
					continue
				}
				if nowMs < retryState.NextAllowedUnixMs {
					continue
				}
			}
			sourceEndpoints := buildPunchEndpoints(srcClient)
			targetEndpoints := buildPunchEndpoints(targetClient)
			if len(sourceEndpoints) == 0 || len(targetEndpoints) == 0 {
				continue
			}
			sessionID := uint64(time.Now().UnixNano())
			attempt := uint32(1)
			attemptBudget := uint32(maxPunchAttemptsPerPair)
			if hasRetry {
				attempt = retryState.Attempt + 1
			}
			deadline := now.Add(5 * time.Second).UnixMilli()
			selectionPolicy := pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll
			session := &PunchSession{
				SessionID:       sessionID,
				Source:          srcIP,
				Target:          targetIP,
				Attempt:         attempt,
				AttemptBudget:   attemptBudget,
				DeadlineUnixMs:  deadline,
				TriggerReason:   triggerReason.String(),
				SelectionPolicy: selectionPolicy.String(),
				State:           PunchSessionScheduled,
				RequestedAt:     now.Unix(),
				Ack:             make(map[uint32]bool),
				Results:         make(map[uint32]*pb.PunchResult),
			}
			c.nc.PunchSessions.Set(punchSessionKey(sessionID, attempt), session)
			c.nc.PunchPairCooldown.Set(pairKey, struct{}{})
			sourceStart := &pb.PunchStart{
				SessionId:               sessionID,
				Source:                  srcIP,
				Target:                  targetIP,
				PeerEndpoints:           targetEndpoints,
				Attempt:                 attempt,
				TimeoutMs:               3000,
				DeadlineUnixMs:          deadline,
				TriggerReason:           triggerReason,
				AttemptBudget:           attemptBudget,
				EndpointSelectionPolicy: selectionPolicy,
			}
			targetStart := &pb.PunchStart{
				SessionId:               sessionID,
				Source:                  targetIP,
				Target:                  srcIP,
				PeerEndpoints:           sourceEndpoints,
				Attempt:                 attempt,
				TimeoutMs:               3000,
				DeadlineUnixMs:          deadline,
				TriggerReason:           triggerReason,
				AttemptBudget:           attemptBudget,
				EndpointSelectionPolicy: selectionPolicy,
			}
			sourcePayload, err := proto.Marshal(sourceStart)
			if err != nil {
				return nil, fmt.Errorf("PunchStart source marshal error: %v", err)
			}
			targetPayload, err := proto.Marshal(targetStart)
			if err != nil {
				return nil, fmt.Errorf("PunchStart target marshal error: %v", err)
			}
			return []*protocol.Packet{
				{
					Ver:             protocol.V3,
					Proto:           protocol.ProtocolService,
					AppProto:        protocol.AppProtoPunchStart,
					SourceTTL:       protocol.MAX_TTL,
					TTL:             protocol.MAX_TTL,
					SrcIP:           request.DstIP,
					DstIP:           util.Uint32ToIP(srcIP),
					Payload:         sourcePayload,
					RouteNetworkKey: key,
				},
				{
					Ver:             protocol.V3,
					Proto:           protocol.ProtocolService,
					AppProto:        protocol.AppProtoPunchStart,
					SourceTTL:       protocol.MAX_TTL,
					TTL:             protocol.MAX_TTL,
					SrcIP:           request.DstIP,
					DstIP:           util.Uint32ToIP(targetIP),
					Payload:         targetPayload,
					RouteNetworkKey: key,
				},
			}, nil
		}
	}
	return nil, nil
}

func clientReportsDirectPeer(client ClientInfo, peerIP uint32) bool {
	if client.ClientStatus == nil {
		return false
	}
	peer := util.Uint32ToIP(peerIP)
	for _, ip := range client.ClientStatus.P2PList {
		if ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
}

func clientsHaveAnyP2PPath(srcClient ClientInfo, srcIP uint32, targetClient ClientInfo, targetIP uint32) bool {
	return clientReportsDirectPeer(srcClient, targetIP) || clientReportsDirectPeer(targetClient, srcIP)
}

func clientsHaveMutualP2PPath(srcClient ClientInfo, srcIP uint32, targetClient ClientInfo, targetIP uint32) bool {
	return clientReportsDirectPeer(srcClient, targetIP) && clientReportsDirectPeer(targetClient, srcIP)
}

func shouldSuppressPunchStartForStatusUpdate(
	srcClient ClientInfo,
	srcIP uint32,
	targetClient ClientInfo,
	targetIP uint32,
) bool {
	return clientsHaveAnyP2PPath(srcClient, srcIP, targetClient, targetIP)
}

func shouldSuppressPunchStartForOtherTrigger(
	srcClient ClientInfo,
	srcIP uint32,
	targetClient ClientInfo,
	targetIP uint32,
) bool {
	return clientsHaveMutualP2PPath(srcClient, srcIP, targetClient, targetIP)
}

func (c *Controller) HandlePunchRequestPacket(request *protocol.Packet) (*protocol.Packet, error) {
	return c.HandlePunchRequestPacketInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) HandlePunchRequestPacketInNetwork(request *protocol.Packet, networkKey string) (*protocol.Packet, error) {
	var req pb.PunchRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, fmt.Errorf("PunchRequest unmarshal error: %v", err)
	}
	sourceIP := util.IpToUint32(request.SrcIP)
	if req.GetSource() != 0 && req.GetSource() != sourceIP {
		return nil, fmt.Errorf("punch request source mismatch: %d != %d", req.GetSource(), sourceIP)
	}
	if req.GetSessionId() == 0 || req.GetAttempt() == 0 {
		return nil, fmt.Errorf("invalid punch request, session_id and attempt must be non-zero")
	}
	if _, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, req.GetTarget()); !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	now := time.Now().Unix()
	session := &PunchSession{
		SessionID:       req.GetSessionId(),
		Source:          sourceIP,
		Target:          req.GetTarget(),
		Attempt:         req.GetAttempt(),
		AttemptBudget:   req.GetAttemptBudget(),
		DeadlineUnixMs:  req.GetDeadlineUnixMs(),
		TriggerReason:   req.GetTriggerReason().String(),
		SelectionPolicy: req.GetEndpointSelectionPolicy().String(),
		State:           PunchSessionScheduled,
		RequestedAt:     now,
		Ack:             map[uint32]bool{sourceIP: true},
		Results:         make(map[uint32]*pb.PunchResult),
	}
	if session.DeadlineUnixMs == 0 {
		session.DeadlineUnixMs = time.Now().Add(5 * time.Second).UnixMilli()
	}
	if session.AttemptBudget == 0 {
		session.AttemptBudget = maxPunchAttemptsPerPair
	}
	c.nc.PunchSessions.Set(punchSessionKey(req.GetSessionId(), req.GetAttempt()), session)
	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    sourceIP,
		Attempt:   req.GetAttempt(),
		Accepted:  true,
		Phase:     pb.PunchSessionPhase_PunchPhaseScheduled,
	}
	payload, err := proto.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("PunchAck marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPunchAck,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) BuildPunchStartPackets(request *protocol.Packet) ([]*protocol.Packet, error) {
	return c.BuildPunchStartPacketsInNetwork(request, request.RouteNetworkKey)
}

func (c *Controller) BuildPunchStartPacketsInNetwork(request *protocol.Packet, networkKey string) ([]*protocol.Packet, error) {
	var req pb.PunchRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, fmt.Errorf("PunchRequest unmarshal error: %v", err)
	}
	sourceIP := util.IpToUint32(request.SrcIP)
	if req.GetSource() != 0 && req.GetSource() != sourceIP {
		return nil, fmt.Errorf("punch request source mismatch: %d != %d", req.GetSource(), sourceIP)
	}
	if req.GetSessionId() == 0 || req.GetAttempt() == 0 {
		return nil, fmt.Errorf("invalid punch request, session_id and attempt must be non-zero")
	}
	if _, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, sourceIP); !ok {
		return nil, fmt.Errorf("punch source %s not registered", util.Uint32ToIP(sourceIP))
	}
	if _, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, req.GetTarget()); !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	sourceStart := &pb.PunchStart{
		SessionId:               req.GetSessionId(),
		Source:                  sourceIP,
		Target:                  req.GetTarget(),
		PeerEndpoints:           req.GetTargetEndpoints(),
		Attempt:                 req.GetAttempt(),
		TimeoutMs:               req.GetTimeoutMs(),
		DeadlineUnixMs:          req.GetDeadlineUnixMs(),
		TriggerReason:           req.GetTriggerReason(),
		AttemptBudget:           req.GetAttemptBudget(),
		EndpointSelectionPolicy: req.GetEndpointSelectionPolicy(),
	}
	targetStart := &pb.PunchStart{
		SessionId:               req.GetSessionId(),
		Source:                  req.GetTarget(),
		Target:                  sourceIP,
		PeerEndpoints:           req.GetSourceEndpoints(),
		Attempt:                 req.GetAttempt(),
		TimeoutMs:               req.GetTimeoutMs(),
		DeadlineUnixMs:          req.GetDeadlineUnixMs(),
		TriggerReason:           req.GetTriggerReason(),
		AttemptBudget:           req.GetAttemptBudget(),
		EndpointSelectionPolicy: req.GetEndpointSelectionPolicy(),
	}
	sourcePayload, err := proto.Marshal(sourceStart)
	if err != nil {
		return nil, fmt.Errorf("PunchStart source marshal error: %v", err)
	}
	targetPayload, err := proto.Marshal(targetStart)
	if err != nil {
		return nil, fmt.Errorf("PunchStart target marshal error: %v", err)
	}
	return []*protocol.Packet{
		{
			Ver:             protocol.V3,
			Proto:           protocol.ProtocolService,
			AppProto:        protocol.AppProtoPunchStart,
			SourceTTL:       protocol.MAX_TTL,
			TTL:             protocol.MAX_TTL,
			SrcIP:           request.DstIP,
			DstIP:           util.Uint32ToIP(sourceIP),
			Payload:         sourcePayload,
			RouteNetworkKey: networkKey,
		},
		{
			Ver:             protocol.V3,
			Proto:           protocol.ProtocolService,
			AppProto:        protocol.AppProtoPunchStart,
			SourceTTL:       protocol.MAX_TTL,
			TTL:             protocol.MAX_TTL,
			SrcIP:           request.DstIP,
			DstIP:           util.Uint32ToIP(req.GetTarget()),
			Payload:         targetPayload,
			RouteNetworkKey: networkKey,
		},
	}, nil
}

func (c *Controller) HandlePunchAckPacket(request *protocol.Packet) error {
	var ack pb.PunchAck
	if err := proto.Unmarshal(request.Payload, &ack); err != nil {
		return fmt.Errorf("PunchAck unmarshal error: %v", err)
	}
	key := punchSessionKey(ack.GetSessionId(), ack.GetAttempt())
	session, ok := c.nc.PunchSessions.Get(key)
	if !ok {
		return fmt.Errorf("punch session not found: %s", key)
	}
	source := util.IpToUint32(request.SrcIP)
	if ack.GetSource() != 0 && ack.GetSource() != source {
		return fmt.Errorf("punch ack source mismatch: %d != %d", ack.GetSource(), source)
	}
	if session.Ack == nil {
		session.Ack = make(map[uint32]bool)
	}
	if session.Results == nil {
		session.Results = make(map[uint32]*pb.PunchResult)
	}
	peer := punchPeerIP(session, source)
	log.Debugf(
		"PunchAck detail src=%s dst=%s session_id=%d attempt=%d accepted=%v phase=%s reason=%q",
		request.SrcIP,
		formatPunchIP(peer),
		ack.GetSessionId(),
		ack.GetAttempt(),
		ack.GetAccepted(),
		ack.GetPhase().String(),
		ack.GetReason(),
	)
	session.Ack[source] = ack.GetAccepted()
	pairKey := punchPairKey(session.Source, session.Target)
	if !ack.GetAccepted() {
		session.State = PunchSessionFailed
		session.LastReason = ack.GetReason()
		session.RelayFallback = true
		c.nc.PunchPairCooldown.Delete(pairKey)
		c.updatePunchRetryState(pairKey, session.State)
	} else if len(session.Ack) >= 2 {
		session.State = PunchSessionWaiting
	} else {
		session.State = punchSessionStateFromPhase(ack.GetPhase())
		if session.State == PunchSessionScheduled {
			session.State = PunchSessionSending
		}
	}
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) HandlePunchResultPacket(request *protocol.Packet) error {
	var result pb.PunchResult
	if err := proto.Unmarshal(request.Payload, &result); err != nil {
		return fmt.Errorf("PunchResult unmarshal error: %v", err)
	}
	key := punchSessionKey(result.GetSessionId(), result.GetAttempt())
	session, ok := c.nc.PunchSessions.Get(key)
	if !ok {
		return fmt.Errorf("punch session not found: %s", key)
	}
	source := util.IpToUint32(request.SrcIP)
	if result.GetSource() != 0 && result.GetSource() != source {
		return fmt.Errorf("punch result source mismatch: %d != %d", result.GetSource(), source)
	}
	if session.Ack == nil {
		session.Ack = make(map[uint32]bool)
	}
	if session.Results == nil {
		session.Results = make(map[uint32]*pb.PunchResult)
	}
	peer := punchPeerIP(session, source)
	if result.GetCode() == pb.PunchResultCode_PunchResultSuccess {
		log.Debugf(
			"PunchResult detail src=%s dst=%s session_id=%d attempt=%d phase=%s code=%s reason=%q selected_endpoint=%s",
			request.SrcIP,
			formatPunchIP(peer),
			result.GetSessionId(),
			result.GetAttempt(),
			result.GetPhase().String(),
			result.GetCode().String(),
			result.GetReason(),
			formatPunchEndpoint(result.GetSelectedEndpoint()),
		)
	} else {
		log.Infof(
			"PunchResult detail src=%s dst=%s session_id=%d attempt=%d phase=%s code=%s reason=%q selected_endpoint=%s",
			request.SrcIP,
			formatPunchIP(peer),
			result.GetSessionId(),
			result.GetAttempt(),
			result.GetPhase().String(),
			result.GetCode().String(),
			result.GetReason(),
			formatPunchEndpoint(result.GetSelectedEndpoint()),
		)
	}
	session.Results[source] = &result
	pairKey := punchPairKey(session.Source, session.Target)
	switch result.GetCode() {
	case pb.PunchResultCode_PunchResultSuccess:
		session.State = PunchSessionSuccess
		session.RelayFallback = false
	case pb.PunchResultCode_PunchResultTimeout, pb.PunchResultCode_PunchResultNoResponse:
		session.State = PunchSessionTimeout
		session.RelayFallback = true
	default:
		session.State = punchSessionStateFromPhase(result.GetPhase())
		if session.State != PunchSessionFailed {
			session.State = PunchSessionFailed
		}
		session.RelayFallback = true
	}
	session.LastReason = result.GetReason()
	c.nc.PunchPairCooldown.Delete(pairKey)
	c.updatePunchRetryState(pairKey, session.State)
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) ReconcilePunchSessions(nowUnixMs int64) {
	c.nc.PunchSessions.mutex.Lock()
	defer c.nc.PunchSessions.mutex.Unlock()
	for key, session := range c.nc.PunchSessions.data {
		if session == nil {
			continue
		}
		if (session.State == PunchSessionScheduled || session.State == PunchSessionSending || session.State == PunchSessionWaiting) &&
			session.DeadlineUnixMs > 0 && nowUnixMs > session.DeadlineUnixMs {
			session.State = PunchSessionTimeout
			if session.LastReason == "" {
				session.LastReason = "deadline exceeded"
			}
			session.RelayFallback = true
			c.nc.PunchSessions.data[key] = session
			pairKey := punchPairKey(session.Source, session.Target)
			c.nc.PunchPairCooldown.Delete(pairKey)
			c.updatePunchRetryState(pairKey, session.State)
		}
	}
}

func (c *Controller) HandleControlPacket(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	return c.HandleControlPacketInNetwork(request, remoteAddr, request.RouteNetworkKey)
}

func (c *Controller) HandleControlPacketInNetwork(request *protocol.Packet, remoteAddr net.Addr, networkKey string) (*protocol.Packet, error) {
	switch protocol.ControlProtocol(request.AppProto) {
	case protocol.ControlPing:
		pingTime, _, err := protocol.ParsePingPayload(request.Payload)
		if err != nil {
			return nil, err
		}
		epoch := c.nc.TouchClientByIPInNetwork(networkKey, request.SrcIP)
		if epoch == 0 {
			log.Warnf("received control ping from srcIP=%s but client touch failed, sending disconnect packet", request.SrcIP)
			return c.buildDisconnectPacket(request), nil
		}
		payload := protocol.BuildPingPayload(pingTime, epoch)
		return &protocol.Packet{
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlPong),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Payload:   payload,
		}, nil
	case protocol.ControlAddrRequest:
		payload, err := protocol.BuildAddrPayloadByAddr(remoteAddr)
		if err != nil {
			return nil, err
		}
		return &protocol.Packet{
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlAddrResponse),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Payload:   payload,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported control protocol: %d", request.AppProto)
	}
}

func punchSessionKey(sessionID uint64, attempt uint32) string {
	return fmt.Sprintf("%d:%d", sessionID, attempt)
}

func punchPairKey(a, b uint32) string {
	if a < b {
		return fmt.Sprintf("%d-%d", a, b)
	}
	return fmt.Sprintf("%d-%d", b, a)
}

func retryBackoffDuration(attempt uint32) time.Duration {
	if attempt == 0 {
		return 0
	}
	shift := attempt
	if shift > 5 {
		shift = 5
	}
	d := time.Duration(1<<shift) * time.Second
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

func punchSessionStateFromPhase(phase pb.PunchSessionPhase) PunchSessionState {
	switch phase {
	case pb.PunchSessionPhase_PunchPhaseScheduled, pb.PunchSessionPhase_PunchPhaseUnknown:
		return PunchSessionScheduled
	case pb.PunchSessionPhase_PunchPhaseSending:
		return PunchSessionSending
	case pb.PunchSessionPhase_PunchPhaseWaiting:
		return PunchSessionWaiting
	case pb.PunchSessionPhase_PunchPhaseSuccess:
		return PunchSessionSuccess
	case pb.PunchSessionPhase_PunchPhaseTimeout:
		return PunchSessionTimeout
	case pb.PunchSessionPhase_PunchPhaseFailed:
		return PunchSessionFailed
	default:
		return PunchSessionFailed
	}
}

func (c *Controller) updatePunchRetryState(pairKey string, status PunchSessionState) {
	switch status {
	case PunchSessionSuccess:
		c.nc.PunchPairRetry.Delete(pairKey)
	case PunchSessionFailed, PunchSessionTimeout:
		state, _ := c.nc.PunchPairRetry.Get(pairKey)
		state.Attempt++
		state.NextAllowedUnixMs = time.Now().Add(retryBackoffDuration(state.Attempt)).UnixMilli()
		c.nc.PunchPairRetry.Set(pairKey, state)
	}
}

func buildPunchEndpoints(client ClientInfo) []*pb.PunchEndpoint {
	status := client.ClientStatus
	if status == nil {
		return nil
	}
	endpoints := make([]*pb.PunchEndpoint, 0, len(status.PublicUDPEndpoints)+len(status.LocalUDPEndpoints))
	seen := make(map[string]struct{})
	appendEndpoint := func(ip net.IP, port uint16) {
		if port == 0 {
			return
		}
		if ip == nil {
			return
		}
		var endpoint *pb.PunchEndpoint
		if ipv4 := ip.To4(); ipv4 != nil {
			endpoint = &pb.PunchEndpoint{
				Ip:   util.IpToUint32(ipv4),
				Port: uint32(port),
				Tcp:  false,
			}
		} else if ipv6 := ip.To16(); len(ipv6) == net.IPv6len {
			endpoint = &pb.PunchEndpoint{
				Ipv6: append([]byte(nil), ipv6...),
				Port: uint32(port),
				Tcp:  false,
			}
		} else {
			return
		}
		key := ip.String() + ":" + strconv.Itoa(int(port))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	for _, endpoint := range status.PublicUDPEndpoints {
		if endpoint == nil {
			continue
		}
		appendEndpoint(endpoint.IP, uint16(endpoint.Port))
	}
	for _, endpoint := range status.LocalUDPEndpoints {
		if endpoint == nil {
			continue
		}
		appendEndpoint(endpoint.IP, uint16(endpoint.Port))
	}
	return endpoints
}

func punchPeerIP(session *PunchSession, source uint32) uint32 {
	if session == nil {
		return 0
	}
	switch source {
	case session.Source:
		return session.Target
	case session.Target:
		return session.Source
	default:
		return 0
	}
}

func formatPunchIP(ip uint32) string {
	if ip == 0 {
		return "-"
	}
	return util.Uint32ToIP(ip).String()
}

func formatPunchEndpoint(endpoint *pb.PunchEndpoint) string {
	if endpoint == nil {
		return "-"
	}
	protoName := "udp"
	if endpoint.GetTcp() {
		protoName = "tcp"
	}
	if ipv6 := net.IP(endpoint.GetIpv6()); len(ipv6) > 0 {
		return fmt.Sprintf("[%s]:%d/%s", ipv6.String(), endpoint.GetPort(), protoName)
	}
	if endpoint.GetIp() == 0 {
		return fmt.Sprintf("-:%d/%s", endpoint.GetPort(), protoName)
	}
	return fmt.Sprintf("%s:%d/%s", util.Uint32ToIP(endpoint.GetIp()), endpoint.GetPort(), protoName)
}

func (c *Controller) setPendingHandshakeCapabilities(remoteAddr net.Addr, capabilities []string) {
	if remoteAddr == nil {
		return
	}
	c.mu.Lock()
	c.handshakeCaps[remoteAddr.String()] = append([]string(nil), capabilities...)
	c.mu.Unlock()
}

func (c *Controller) pendingHandshakeCapabilities(remoteAddr net.Addr) []string {
	if remoteAddr == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.handshakeCaps[remoteAddr.String()]...)
}

func (c *Controller) clearPendingHandshakeCapabilities(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	c.mu.Lock()
	delete(c.handshakeCaps, remoteAddr.String())
	c.mu.Unlock()
}

func hasCapability(capabilities []string, capability string) bool {
	for _, item := range capabilities {
		if item == capability {
			return true
		}
	}
	return false
}

type NetworkControl struct {
	//
	VirtualNetwork ExpireMap[string, *NetworkInfo]
	// 用来做地址分配和回收
	IPSessions ExpireMap[IpSessionKey, net.Addr]
	// 链路上的加密会话上下文占位（按远端地址跟踪）
	CipherSessions ExpireMap[string, struct{}]
	// 打洞会话状态（session_id + attempt）
	PunchSessions ExpireMap[string, *PunchSession]
	// 打洞触发冷却（pair key）
	PunchPairCooldown ExpireMap[string, struct{}]
	// 打洞重试状态（pair key）
	PunchPairRetry ExpireMap[string, PunchRetryState]
}

// IpSessionKey is a comparable key for IPSessions.
// Use string fields because net.IP (a []byte) is not comparable.
type IpSessionKey struct {
	ID string // domain
	IP string // use net.IP.String()
}

// compile-time check: ensure IpSessionKey is comparable (map key). If IpSessionKey contains
// a non-comparable field (e.g. slice), this will fail to compile.
var _ map[IpSessionKey]struct{} = nil

// NewIpSessionKey builds an IpSessionKey from an id and net.IP.
func NewIpSessionKey(id string, ip net.IP) IpSessionKey {
	return IpSessionKey{
		ID: id,
		IP: ip.String(),
	}
}

func networkScopeForAuth(groupName, userID string) string {
	return NewNetworkIdentity(groupName, userID).Scope()
}

func isPersonalSDLUser(userID string) bool {
	return strings.HasPrefix(strings.TrimSpace(userID), personalUserIDPrefix)
}

func clientAuthGroup(client ClientInfo, fallback string) string {
	return NetworkIdentityFromClient(client, fallback).AuthGroup()
}

func clientNetworkKey(client ClientInfo, fallback string) string {
	return NetworkIdentityFromClient(client, fallback).Key()
}

func clientNetworkScope(client ClientInfo, fallbackGroup string) string {
	return NetworkIdentityFromClient(client, fallbackGroup).Scope()
}

func parseNetmask(netmask string) (net.IPMask, error) {
	ip := net.ParseIP(netmask)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid netmask %q", netmask)
	}
	return net.IPMask(ip.To4()), nil
}

func (c *Controller) resolveGroupNetworkConfig(group string) (net.IP, net.IPMask, error) {
	if len(c.cfg.Domains) > 0 {
		domainName, groupName, ok := matchDomainAndGroup(group, c.cfg.Domains)
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured in domains (expect <group>.<domain>)", group)
		}
		dc := c.cfg.Domains[domainName]
		gc, ok := dc.Groups[groupName]
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured under domain %s", groupName, domainName)
		}
		mask, err := parseNetmask(gc.Netmask)
		if err != nil {
			return nil, nil, err
		}
		return gc.Gateway, mask, nil
	}
	if len(c.cfg.Groups) > 0 {
		gc, ok := c.cfg.Groups[group]
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured", group)
		}
		mask, err := parseNetmask(gc.Netmask)
		if err != nil {
			return nil, nil, err
		}
		return gc.Gateway, mask, nil
	}
	if c.cfg.Domain != "" && group != c.cfg.Domain {
		return nil, nil, fmt.Errorf("RegistrationRequest domain %s mismatch config domain %s", group, c.cfg.Domain)
	}
	mask, err := parseNetmask(c.cfg.Netmask)
	if err != nil {
		return nil, nil, err
	}
	return c.cfg.Gateway, mask, nil
}

func (c *Controller) HandleGatewayReportPacket(packet *protocol.Packet) (*protocol.Packet, error) {
	var req pb.GatewayReportRequest
	if err := proto.Unmarshal(packet.Payload, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetGatewayId()) == "" {
		return nil, fmt.Errorf("gateway_id is required")
	}
	if req.GetGatewayChannel() == nil {
		return nil, fmt.Errorf("gateway_channel is required")
	}
	if req.GetReportUnixMs() == 0 {
		return nil, fmt.Errorf("report_unix_ms is required")
	}
	normalizedChannels := cloneGatewayChannels([]*pb.GatewayChannel{req.GetGatewayChannel()})
	primaryEndpoint := primaryGatewayEndpoint(normalizedChannels)
	if primaryEndpoint == "" {
		return nil, fmt.Errorf("gateway_channel must include a valid addr")
	}
	channel := normalizedChannels[0]
	if channel.GetKind() == pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP &&
		(len(channel.GetUdpPublicKey()) != 32 || channel.GetUdpKeyId() == "") {
		return nil, fmt.Errorf("UDP gateway_channel requires a 32-byte udp_public_key and udp_key_id")
	}
	if strings.TrimSpace(req.GetGatewayId()) == strings.TrimSpace(c.cfg.DefaultGatewayID) &&
		gatewayServerName(primaryEndpoint) != defaultGatewayHost {
		return nil, fmt.Errorf("default gateway host must be %s", defaultGatewayHost)
	}
	now := time.Now()
	if err := c.authenticateGatewayReport(&req, now); err != nil {
		return c.buildGatewayReportAck(packet, &pb.GatewayReportAck{
			Ok:           false,
			Reason:       err.Error(),
			GatewayId:    req.GetGatewayId(),
			ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
		})
	}
	c.recordGatewaySeen(GatewayNodeInfo{
		GatewayID:    req.GetGatewayId(),
		Endpoint:     primaryEndpoint,
		Capabilities: append([]string{}, req.GetCapabilities()...),
		Channels:     normalizedChannels,
		UpdatedAt:    now,
	})
	if !c.isGatewayAllowed(req.GetGatewayId(), primaryEndpoint) {
		return c.buildGatewayReportAck(packet, &pb.GatewayReportAck{
			Ok:           false,
			Reason:       "gateway not approved",
			GatewayId:    req.GetGatewayId(),
			ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
		})
	}
	c.RegisterGatewayNodeWithTransport(
		req.GetGatewayId(),
		req.GetCapabilities(),
		normalizedChannels,
	)

	ack := &pb.GatewayReportAck{
		Ok:           true,
		Reason:       "ok",
		GatewayId:    req.GetGatewayId(),
		ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
	}
	return c.buildGatewayReportAck(packet, ack)
}

func (c *Controller) authenticateGatewayReport(req *pb.GatewayReportRequest, now time.Time) error {
	if len(req.GetNonce()) == 0 {
		return fmt.Errorf("nonce is required")
	}
	if len(req.GetSignature()) == 0 {
		return fmt.Errorf("signature is required")
	}
	proofBytes, err := marshalGatewayReportProof(req)
	if err != nil {
		return fmt.Errorf("invalid_gateway_report_proof: %w", err)
	}
	gatewayID := strings.TrimSpace(req.GetGatewayId())
	mac := hmac.New(sha256.New, []byte(c.cfg.GatewayTicketSecret))
	if _, err := mac.Write(proofBytes); err != nil {
		return fmt.Errorf("invalid_gateway_report_proof: %w", err)
	}
	if !hmac.Equal(mac.Sum(nil), req.GetSignature()) {
		return fmt.Errorf("invalid_signature")
	}
	return c.validateGatewayReplayWindow(gatewayID, req.GetReportUnixMs(), req.GetNonce(), now)
}

func marshalGatewayReportProof(req *pb.GatewayReportRequest) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&pb.GatewayReportProof{
		GatewayId:      req.GetGatewayId(),
		Capabilities:   append([]string{}, req.GetCapabilities()...),
		ReportUnixMs:   req.GetReportUnixMs(),
		Nonce:          append([]byte(nil), req.GetNonce()...),
		GatewayChannel: cloneGatewayChannel(req.GetGatewayChannel()),
	})
}

func (c *Controller) validateGatewayReplayWindow(gatewayID string, reportUnixMs int64, nonce []byte, now time.Time) error {
	reportTime := time.UnixMilli(reportUnixMs)
	if now.Sub(reportTime) > gatewayReportFreshnessWindow || reportTime.Sub(now) > gatewayReportFreshnessWindow {
		return fmt.Errorf("stale_report_timestamp")
	}
	nonceKey := hex.EncodeToString(nonce)
	expireAt := reportTime.Add(gatewayReportFreshnessWindow).UnixMilli()
	if expireAt < now.UnixMilli() {
		expireAt = now.Add(gatewayReportFreshnessWindow).UnixMilli()
	}
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	cache := c.gatewayNonce[gatewayID]
	if cache == nil {
		cache = make(map[string]int64)
		c.gatewayNonce[gatewayID] = cache
	}
	nowUnixMs := now.UnixMilli()
	for key, nonceExpireAt := range cache {
		if nonceExpireAt <= nowUnixMs {
			delete(cache, key)
		}
	}
	if _, ok := cache[nonceKey]; ok {
		return fmt.Errorf("replayed_nonce")
	}
	cache[nonceKey] = expireAt
	return nil
}

func (c *Controller) buildGatewayReportAck(packet *protocol.Packet, ack *pb.GatewayReportAck) (*protocol.Packet, error) {
	payload, err := proto.Marshal(ack)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoGatewayReportAck,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     packet.DstIP,
		DstIP:     packet.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) ApproveGatewayNode(gatewayID, endpoint string) {
	c.gatewayMu.Lock()
	c.gatewayAllow[gatewayID] = endpoint
	c.persistGatewayApprovalLocked()
	c.gatewayMu.Unlock()
}

func (c *Controller) ApproveGatewayNodeByID(gatewayID string) error {
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return fmt.Errorf("gateway_id is required")
	}
	if gatewayID == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		return nil
	}
	if endpoint, ok := c.gatewayAllow[gatewayID]; ok && strings.TrimSpace(endpoint) != "" {
		return nil
	}
	seen, ok := c.gatewaySeen[gatewayID]
	if !ok || strings.TrimSpace(seen.Endpoint) == "" {
		return fmt.Errorf("gateway %s has no pending report", gatewayID)
	}
	c.gatewayAllow[gatewayID] = seen.Endpoint
	c.gatewayNodes[gatewayID] = seen
	c.persistGatewayApprovalLocked()
	return nil
}

func (c *Controller) DelistGatewayNodeByID(gatewayID string) error {
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return fmt.Errorf("gateway_id is required")
	}
	if gatewayID == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		return fmt.Errorf("default gateway %s cannot be delisted", gatewayID)
	}
	_, allowed := c.gatewayAllow[gatewayID]
	node, active := c.gatewayNodes[gatewayID]
	_, seen := c.gatewaySeen[gatewayID]
	if !allowed && !active && !seen {
		return fmt.Errorf("gateway %s not found", gatewayID)
	}
	if active {
		c.gatewaySeen[gatewayID] = node
	}
	delete(c.gatewayAllow, gatewayID)
	delete(c.gatewayNodes, gatewayID)
	c.deleteGatewayGrantCacheForGatewayLocked(gatewayID)
	c.persistGatewayApprovalLocked()
	return nil
}

func (c *Controller) ListGateways() []GatewayAdminView {
	c.gatewayMu.RLock()
	defer c.gatewayMu.RUnlock()
	now := time.Now()
	byID := map[string]GatewayAdminView{}
	defaultID := strings.TrimSpace(c.cfg.DefaultGatewayID)
	for gatewayID, endpoint := range c.gatewayAllow {
		item := byID[gatewayID]
		item.GatewayID = gatewayID
		item.Endpoint = endpoint
		item.Approved = true
		if gatewayID == defaultID {
			item.Default = true
		}
		byID[gatewayID] = item
	}
	for gatewayID, seen := range c.gatewaySeen {
		item, ok := byID[gatewayID]
		if !ok {
			item = GatewayAdminView{
				GatewayID: gatewayID,
				Endpoint:  seen.Endpoint,
			}
		}
		if strings.TrimSpace(item.Endpoint) == "" {
			item.Endpoint = seen.Endpoint
		}
		item.Reported = true
		item.Alive = now.Sub(seen.UpdatedAt) <= gatewayNodeLease
		item.Capabilities = append([]string{}, seen.Capabilities...)
		item.UpdatedAtUnix = seen.UpdatedAt.Unix()
		byID[gatewayID] = item
	}
	for gatewayID, item := range byID {
		if node, ok := c.gatewayNodes[gatewayID]; ok && (strings.TrimSpace(item.Endpoint) == "" || strings.TrimSpace(node.Endpoint) == strings.TrimSpace(item.Endpoint)) {
			item.Endpoint = node.Endpoint
			item.Reported = true
			item.Alive = now.Sub(node.UpdatedAt) <= gatewayNodeLease
			item.Capabilities = append([]string{}, node.Capabilities...)
			item.UpdatedAtUnix = node.UpdatedAt.Unix()
			byID[gatewayID] = item
		}
	}
	result := make([]GatewayAdminView, 0, len(byID))
	for _, item := range byID {
		result = append(result, item)
	}
	return result
}

func (c *Controller) ListDevices(userID string) []DeviceAdminView {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	records := c.um.ListAuthedDevicesByUser(userID)
	if len(records) == 0 {
		return nil
	}
	deviceByGroupDevice := make(map[string]DeviceAdminView, len(records))
	for _, record := range records {
		name := strings.TrimSpace(record.DisplayName)
		if name == "" {
			name = record.DeviceID
		}
		deviceByGroupDevice[record.GroupName+"\x00"+record.DeviceID] = DeviceAdminView{
			UserID:           record.UserID,
			Group:            record.GroupName,
			Name:             name,
			DeviceID:         record.DeviceID,
			AuthedAtUnix:     record.AuthedAt.Unix(),
			AuthExpireAtUnix: record.AuthExpireAt.Unix(),
			AuthExpired:      !record.AuthExpireAt.IsZero() && time.Now().After(record.AuthExpireAt),
			UpdatedAtUnix:    record.AuthedAt.Unix(),
		}
	}

	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()

	for _, network := range c.nc.VirtualNetwork.data {
		for ip, client := range network.Clients {
			authGroup := clientAuthGroup(client, network.Group)
			key := authGroup + "\x00" + client.DeviceId
			device, ok := deviceByGroupDevice[key]
			if !ok {
				continue
			}
			updatedAt := client.ControlLastSeen
			if client.DataPlaneLastSeen > updatedAt {
				updatedAt = client.DataPlaneLastSeen
			}
			if client.LastJoin > updatedAt {
				updatedAt = client.LastJoin
			}
			if strings.TrimSpace(client.Name) != "" {
				device.Name = client.Name
			}
			device.Group = authGroup
			device.VirtualIP = util.Uint32ToIP(ip).String()
			device.ControlOnline = client.ControlOnline
			device.DataPlaneReachable = client.DataPlaneReachable
			if updatedAt > device.UpdatedAtUnix {
				device.UpdatedAtUnix = updatedAt
			}
			deviceByGroupDevice[key] = device
		}
	}

	devices := make([]DeviceAdminView, 0, len(deviceByGroupDevice))
	for _, device := range deviceByGroupDevice {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Group != devices[j].Group {
			return devices[i].Group < devices[j].Group
		}
		if devices[i].UserID != devices[j].UserID {
			return devices[i].UserID < devices[j].UserID
		}
		if devices[i].Name != devices[j].Name {
			return devices[i].Name < devices[j].Name
		}
		if devices[i].VirtualIP != devices[j].VirtualIP {
			return devices[i].VirtualIP < devices[j].VirtualIP
		}
		return devices[i].DeviceID < devices[j].DeviceID
	})
	return devices
}

func (c *Controller) isGatewayAllowed(gatewayID, endpoint string) bool {
	c.gatewayMu.RLock()
	defer c.gatewayMu.RUnlock()
	if strings.TrimSpace(gatewayID) == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		return true
	}
	allowedEndpoint, ok := c.gatewayAllow[gatewayID]
	return ok && strings.TrimSpace(allowedEndpoint) == strings.TrimSpace(endpoint)
}

func (c *Controller) RegisterGatewayNode(gatewayID, endpoint string, capabilities []string, _ string, _ []byte) {
	c.RegisterGatewayNodeWithTransport(
		gatewayID,
		capabilities,
		[]*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + strings.TrimSpace(endpoint),
			ServerName: gatewayServerName(endpoint),
		}},
	)
}

func (c *Controller) RegisterGatewayNodeWithTransport(
	gatewayID string,
	capabilities []string,
	channels []*pb.GatewayChannel,
) {
	c.gatewayMu.Lock()
	normalizedChannels := cloneGatewayChannels(channels)
	endpoint := primaryGatewayEndpoint(normalizedChannels)
	if endpoint == "" || len(normalizedChannels) == 0 {
		c.gatewayMu.Unlock()
		log.Warnf("skip gateway registration with no valid channels: gateway_id=%s", strings.TrimSpace(gatewayID))
		return
	}
	c.gatewayAllow[gatewayID] = endpoint
	c.gatewayNodes[gatewayID] = GatewayNodeInfo{
		GatewayID:    gatewayID,
		Endpoint:     endpoint,
		Capabilities: append([]string{}, capabilities...),
		Channels:     normalizedChannels,
		UpdatedAt:    time.Now(),
	}
	delete(c.gatewaySeen, gatewayID)
	c.persistGatewayApprovalLocked()
	c.gatewayMu.Unlock()
}

func (c *Controller) recordGatewaySeen(info GatewayNodeInfo) {
	c.gatewayMu.Lock()
	c.gatewaySeen[info.GatewayID] = info
	c.gatewayMu.Unlock()
}

func (c *Controller) buildGatewayAccessGrant(networkKey string, virtualIP uint32, deviceID string) *pb.GatewayAccessGrant {
	return selectPrimaryGatewayGrant(c.buildGatewayAccessGrants(networkKey, virtualIP, deviceID))
}

func (c *Controller) buildGatewayAccessGrants(networkKey string, virtualIP uint32, deviceID string) []*pb.GatewayAccessGrant {
	grants, _ := c.buildGatewayAccessGrantsWithPolicyRev(networkKey, virtualIP, deviceID)
	return grants
}

func (c *Controller) buildGatewayAccessGrantsWithPolicyRev(networkKey string, virtualIP uint32, deviceID string) ([]*pb.GatewayAccessGrant, uint64) {
	grants, policyRev, _ := c.buildGatewayAccessGrantsLocked(networkKey, virtualIP, deviceID, gatewayGrantBuildOptions{})
	return grants, policyRev
}

func (c *Controller) buildGatewayAccessGrantsForExistingClient(networkKey string, virtualIP uint32, deviceID string) ([]*pb.GatewayAccessGrant, uint64) {
	grants, policyRev, _ := c.buildGatewayAccessGrantsLocked(networkKey, virtualIP, deviceID, gatewayGrantBuildOptions{
		retainExisting: true,
	})
	return grants, policyRev
}

func (c *Controller) buildGatewayAccessGrantsForRefresh(
	networkKey string,
	virtualIP uint32,
	deviceID string,
	lastSessionID uint64,
	forceReissue bool,
) ([]*pb.GatewayAccessGrant, uint64, bool) {
	return c.buildGatewayAccessGrantsLocked(networkKey, virtualIP, deviceID, gatewayGrantBuildOptions{
		lastSessionID:  lastSessionID,
		forceReissue:   forceReissue,
		refresh:        true,
		retainExisting: true,
	})
}

func (c *Controller) buildGatewayAccessGrantsLocked(
	networkKey string,
	virtualIP uint32,
	deviceID string,
	opts gatewayGrantBuildOptions,
) ([]*pb.GatewayAccessGrant, uint64, bool) {
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	now := time.Now()
	nodes := c.approvedAliveGatewayNodesLocked(now)
	policyRev, _ := c.syncGatewayGrantPolicyLocked(nodes)
	c.pruneGatewayGrantCacheLocked(now)
	if len(nodes) == 0 && !opts.retainExisting {
		return nil, policyRev, false
	}
	if opts.refresh && opts.lastSessionID != 0 {
		opts.lastSessionIDValid = c.gatewayGrantSessionKnownLocked(networkKey, virtualIP, deviceID, opts.lastSessionID)
	}
	hardExpire := now.Add(gatewayGrantHardTTL)
	softRefreshAfter := hardExpire.Add(-gatewayGrantSoftRefreshLead)
	leaseSecs := uint32(gatewayGrantLease / time.Second)
	graceSecs := uint32(gatewayGrantGrace / time.Second)
	grants := make([]*pb.GatewayAccessGrant, 0, len(nodes))
	changed := false
	for index, node := range nodes {
		grant, grantChanged := c.gatewayAccessGrantForNodeLocked(
			networkKey,
			virtualIP,
			deviceID,
			node,
			uint64(index),
			hardExpire.UnixMilli(),
			softRefreshAfter.UnixMilli(),
			leaseSecs,
			graceSecs,
			policyRev,
			opts,
			now,
		)
		if grant != nil {
			grants = append(grants, grant)
			changed = changed || grantChanged
		}
	}
	if opts.retainExisting {
		grants = append(grants, c.retainedGatewayAccessGrantsLocked(
			networkKey,
			virtualIP,
			deviceID,
			nodes,
			policyRev,
			now,
		)...)
	}
	sortGatewayAccessGrants(grants, strings.TrimSpace(c.cfg.DefaultGatewayID))
	return grants, policyRev, changed
}

func (c *Controller) gatewayAccessGrantForNodeLocked(
	networkKey string,
	virtualIP uint32,
	deviceID string,
	node GatewayNodeInfo,
	sessionSalt uint64,
	expireUnixMs int64,
	refreshAfterUnixMs int64,
	leaseSecs uint32,
	graceSecs uint32,
	policyRev uint64,
	opts gatewayGrantBuildOptions,
	now time.Time,
) (*pb.GatewayAccessGrant, bool) {
	cacheKey := gatewayGrantCacheKey(networkKey, virtualIP, deviceID, node.GatewayID)
	nodeFingerprint := gatewayGrantNodeFingerprint(node)
	cached, ok := c.gatewayGrantCache[cacheKey]
	if opts.refresh {
		if !opts.forceReissue && ok &&
			cached.nodeFingerprint == nodeFingerprint &&
			cached.grant != nil &&
			cached.expireUnixMs > now.Add(30*time.Second).UnixMilli() {
			if opts.lastSessionID == 0 || opts.lastSessionIDValid {
				grant := cloneGatewayAccessGrant(cached.grant)
				grant.PolicyRev = policyRev
				return grant, false
			}
		}
	} else if ok &&
		cached.nodeFingerprint == nodeFingerprint &&
		cached.grant != nil &&
		cached.expireUnixMs > now.Add(30*time.Second).UnixMilli() {
		grant := cloneGatewayAccessGrant(cached.grant)
		grant.PolicyRev = policyRev
		return grant, false
	}

	sessionID := uint64(now.UnixNano()) + sessionSalt
	if opts.refresh && !opts.forceReissue && opts.lastSessionID != 0 && ok &&
		cached.grant != nil &&
		cached.grant.GetSessionId() == opts.lastSessionID {
		sessionID = opts.lastSessionID
	}
	grant := c.buildGatewayAccessGrantForNode(
		virtualIP,
		deviceID,
		node,
		sessionID,
		expireUnixMs,
		refreshAfterUnixMs,
		leaseSecs,
		graceSecs,
		policyRev,
	)
	if grant == nil {
		delete(c.gatewayGrantCache, cacheKey)
		return nil, false
	}
	c.gatewayGrantCache[cacheKey] = cachedGatewayGrant{
		gatewayID:       node.GatewayID,
		nodeFingerprint: nodeFingerprint,
		expireUnixMs:    grant.GetTicketExpireUnixMs(),
		grant:           cloneGatewayAccessGrant(grant),
	}
	return grant, true
}

func (c *Controller) gatewayGrantSessionKnownLocked(networkKey string, virtualIP uint32, deviceID string, sessionID uint64) bool {
	prefix := gatewayGrantCachePrefix(networkKey, virtualIP, deviceID)
	for key, cacheItem := range c.gatewayGrantCache {
		if strings.HasPrefix(key, prefix) && cacheItem.grant != nil && cacheItem.grant.GetSessionId() == sessionID {
			return true
		}
	}
	return false
}

func (c *Controller) pruneGatewayGrantCacheLocked(now time.Time) {
	expireThreshold := now.Add(30 * time.Second).UnixMilli()
	for key, cached := range c.gatewayGrantCache {
		node, ok := c.gatewayNodes[cached.gatewayID]
		if !ok ||
			!c.gatewayNodeApprovedLocked(node) ||
			cached.grant == nil ||
			cached.expireUnixMs <= expireThreshold ||
			cached.nodeFingerprint != gatewayGrantNodeFingerprint(node) {
			delete(c.gatewayGrantCache, key)
		}
	}
}

func (c *Controller) retainedGatewayAccessGrantsLocked(
	networkKey string,
	virtualIP uint32,
	deviceID string,
	aliveNodes []GatewayNodeInfo,
	policyRev uint64,
	now time.Time,
) []*pb.GatewayAccessGrant {
	alive := make(map[string]struct{}, len(aliveNodes))
	for _, node := range aliveNodes {
		alive[node.GatewayID] = struct{}{}
	}
	prefix := gatewayGrantCachePrefix(networkKey, virtualIP, deviceID)
	expireThreshold := now.Add(30 * time.Second).UnixMilli()
	grants := make([]*pb.GatewayAccessGrant, 0)
	for key, cached := range c.gatewayGrantCache {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if _, ok := alive[cached.gatewayID]; ok {
			continue
		}
		node, ok := c.gatewayNodes[cached.gatewayID]
		if !ok ||
			!c.gatewayNodeApprovedLocked(node) ||
			cached.grant == nil ||
			cached.expireUnixMs <= expireThreshold ||
			cached.nodeFingerprint != gatewayGrantNodeFingerprint(node) {
			continue
		}
		grant := cloneGatewayAccessGrant(cached.grant)
		grant.PolicyRev = policyRev
		grants = append(grants, grant)
	}
	return grants
}

func (c *Controller) deleteGatewayGrantCacheForGatewayLocked(gatewayID string) {
	for key, cached := range c.gatewayGrantCache {
		if cached.gatewayID == gatewayID {
			delete(c.gatewayGrantCache, key)
		}
	}
}

func (c *Controller) buildGatewayAccessGrantForNode(
	virtualIP uint32,
	deviceID string,
	node GatewayNodeInfo,
	sessionID uint64,
	expireUnixMs int64,
	refreshAfterUnixMs int64,
	leaseSecs uint32,
	graceSecs uint32,
	policyRev uint64,
) *pb.GatewayAccessGrant {
	ticket, err := newGatewayTicket(
		c.cfg.GatewayTicketSecret,
		deviceID,
		virtualIP,
		sessionID,
		policyRev,
		[]string{node.GatewayID},
		"",
		expireUnixMs,
		leaseSecs,
		graceSecs,
	)
	if err != nil {
		log.Warnf("build gateway ticket failed for %s: %v", node.GatewayID, err)
		return nil
	}
	grantChannels := cloneGatewayChannels(node.Channels)
	if len(grantChannels) == 0 {
		log.Warnf("skip gateway grant with no valid channels: gateway_id=%s", node.GatewayID)
		return nil
	}
	return &pb.GatewayAccessGrant{
		Ticket:                 ticket,
		TicketExpireUnixMs:     expireUnixMs,
		SessionId:              sessionID,
		PolicyRev:              policyRev,
		GatewayCapabilities:    append([]string{}, node.Capabilities...),
		LeaseSecs:              leaseSecs,
		GraceSecs:              graceSecs,
		GatewayChannel:         cloneGatewayChannel(grantChannels[0]),
		GatewayId:              node.GatewayID,
		SoftRefreshAfterUnixMs: refreshAfterUnixMs,
		HardExpireUnixMs:       expireUnixMs,
	}
}

func (c *Controller) approvedAliveGatewayNodesLocked(now time.Time) []GatewayNodeInfo {
	defaultID := strings.TrimSpace(c.cfg.DefaultGatewayID)
	nodes := make([]GatewayNodeInfo, 0, len(c.gatewayNodes))
	for _, node := range c.gatewayNodes {
		if now.Sub(node.UpdatedAt) > gatewayNodeLease {
			continue
		}
		if !c.gatewayNodeApprovedLocked(node) {
			continue
		}
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		leftDefault := nodes[i].GatewayID == defaultID
		rightDefault := nodes[j].GatewayID == defaultID
		if leftDefault != rightDefault {
			return leftDefault
		}
		if nodes[i].GatewayID != nodes[j].GatewayID {
			return nodes[i].GatewayID < nodes[j].GatewayID
		}
		return nodes[i].Endpoint < nodes[j].Endpoint
	})
	return nodes
}

func (c *Controller) gatewayNodeApprovedLocked(node GatewayNodeInfo) bool {
	if strings.TrimSpace(node.Endpoint) == "" {
		return false
	}
	approvedEndpoint, approved := c.gatewayAllow[node.GatewayID]
	if node.GatewayID == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		approved = true
	}
	if !approved {
		return false
	}
	return strings.TrimSpace(approvedEndpoint) == "" ||
		strings.TrimSpace(approvedEndpoint) == strings.TrimSpace(node.Endpoint)
}

func gatewayGrantFingerprint(nodes []GatewayNodeInfo) string {
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		parts = append(parts, gatewayGrantNodeFingerprint(node))
	}
	return strings.Join(parts, ",")
}

func (c *Controller) syncGatewayGrantPolicyLocked(nodes []GatewayNodeInfo) (uint64, bool) {
	fingerprint := gatewayGrantFingerprint(nodes)
	if fingerprint == c.gatewayGrantFingerprint {
		if c.gatewayGrantPolicyRev == 0 {
			c.gatewayGrantPolicyRev = 1
		}
		return c.gatewayGrantPolicyRev, false
	}
	c.gatewayGrantFingerprint = fingerprint
	c.gatewayGrantPolicyRev++
	if c.gatewayGrantPolicyRev == 0 {
		c.gatewayGrantPolicyRev = 1
	}
	return c.gatewayGrantPolicyRev, true
}

func selectPrimaryGatewayGrant(grants []*pb.GatewayAccessGrant) *pb.GatewayAccessGrant {
	if len(grants) == 0 {
		return nil
	}
	return cloneGatewayAccessGrant(grants[0])
}

func sortGatewayAccessGrants(grants []*pb.GatewayAccessGrant, defaultGatewayID string) {
	sort.Slice(grants, func(i, j int) bool {
		leftDefault := grants[i].GetGatewayId() == defaultGatewayID
		rightDefault := grants[j].GetGatewayId() == defaultGatewayID
		if leftDefault != rightDefault {
			return leftDefault
		}
		return grants[i].GetGatewayId() < grants[j].GetGatewayId()
	})
}

func cloneGatewayAccessGrant(grant *pb.GatewayAccessGrant) *pb.GatewayAccessGrant {
	if grant == nil {
		return nil
	}
	cloned, _ := proto.Clone(grant).(*pb.GatewayAccessGrant)
	return cloned
}

func gatewayGrantCachePrefix(networkKey string, virtualIP uint32, deviceID string) string {
	return fmt.Sprintf("%s|%d|%s|", strings.TrimSpace(networkKey), virtualIP, deviceID)
}

func gatewayGrantCacheKey(networkKey string, virtualIP uint32, deviceID, gatewayID string) string {
	return gatewayGrantCachePrefix(networkKey, virtualIP, deviceID) + gatewayID
}

func gatewayGrantNodeFingerprint(node GatewayNodeInfo) string {
	parts := []string{
		node.GatewayID,
		node.Endpoint,
		strings.Join(node.Capabilities, ","),
	}
	for _, channel := range node.Channels {
		if channel == nil {
			continue
		}
		parts = append(parts, fmt.Sprintf(
			"%d|%s|%s|%s|%x",
			channel.GetKind(),
			channel.GetAddr(),
			channel.GetServerName(),
			channel.GetUdpKeyId(),
			channel.GetUdpPublicKey(),
		))
	}
	return strings.Join(parts, ";")
}

func cloneGatewayChannels(channels []*pb.GatewayChannel) []*pb.GatewayChannel {
	if len(channels) == 0 {
		return nil
	}
	cloned := make([]*pb.GatewayChannel, 0, len(channels))
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		kind := normalizeGatewayChannelKind(channel.GetKind())
		addr := normalizeGatewayChannelAddr(kind, channel.GetAddr())
		if addr == "" {
			continue
		}
		clonedChannel := &pb.GatewayChannel{
			Kind:       kind,
			Addr:       addr,
			ServerName: strings.TrimSpace(channel.GetServerName()),
		}
		if kind == pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP {
			clonedChannel.UdpPublicKey = append([]byte(nil), channel.GetUdpPublicKey()...)
			clonedChannel.UdpKeyId = strings.TrimSpace(channel.GetUdpKeyId())
		}
		cloned = append(cloned, clonedChannel)
	}
	return cloned
}

func cloneGatewayChannel(channel *pb.GatewayChannel) *pb.GatewayChannel {
	channels := cloneGatewayChannels([]*pb.GatewayChannel{channel})
	if len(channels) == 0 {
		return nil
	}
	return channels[0]
}

func normalizeGatewayChannelAddr(kind pb.GatewayChannelKind, raw string) string {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return ""
	}
	if kind != pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS {
		return addr
	}
	if !strings.HasPrefix(addr, "https://") {
		return ""
	}
	uri, err := url.Parse(addr)
	if err != nil || strings.TrimSpace(uri.Host) == "" {
		return ""
	}
	switch path := uri.EscapedPath(); path {
	case "", "/":
		uri.Path = "/gateway"
		uri.RawPath = ""
	case "/gateway":
		uri.Path = "/gateway"
		uri.RawPath = ""
	default:
		return ""
	}
	uri.RawQuery = ""
	uri.Fragment = ""
	return uri.String()
}

func normalizeGatewayChannelKind(kind pb.GatewayChannelKind) pb.GatewayChannelKind {
	switch kind {
	case pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP,
		pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
		pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS:
		return kind
	default:
		return pb.GatewayChannelKind_GATEWAY_CHANNEL_UNKNOWN
	}
}

func primaryGatewayEndpoint(channels []*pb.GatewayChannel) string {
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		kind := normalizeGatewayChannelKind(channel.GetKind())
		addr := normalizeGatewayChannelAddr(kind, channel.GetAddr())
		if addr == "" {
			continue
		}
		switch kind {
		case pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP:
			if strings.HasPrefix(addr, "udp://") {
				endpoint := strings.TrimPrefix(addr, "udp://")
				if endpoint != "" {
					return endpoint
				}
			}
		case pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC:
			if strings.HasPrefix(addr, "quic://") {
				endpoint := strings.TrimPrefix(addr, "quic://")
				if endpoint != "" {
					return endpoint
				}
			}
		case pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS:
			if strings.HasPrefix(addr, "https://") {
				if uri, err := url.Parse(addr); err == nil && uri.Host != "" {
					return uri.Host
				}
			}
		}
	}
	return ""
}

func gatewayServerName(endpoint string) string {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return defaultGatewayHost
	}
	return host
}

func newGatewayTicket(
	secret string,
	deviceID string,
	virtualIP uint32,
	sessionID uint64,
	policyRevision uint64,
	gatewayIDs []string,
	gatewayGroupID string,
	expireUnixMs int64,
	leaseCapSecs uint32,
	graceCapSecs uint32,
) ([]byte, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	nowMs := time.Now().UnixMilli()
	claims := &pb.GatewayTicketClaims{
		TicketId:        fmt.Sprintf("%x", buf),
		DeviceId:        deviceID,
		VirtualIp:       virtualIP,
		SessionId:       sessionID,
		PolicyRevision:  policyRevision,
		GatewayIds:      append([]string{}, gatewayIDs...),
		GatewayGroupId:  gatewayGroupID,
		IssuedAtUnixMs:  nowMs,
		NotBeforeUnixMs: nowMs - 5_000,
		ExpireUnixMs:    expireUnixMs,
		LeaseCapSecs:    leaseCapSecs,
		GraceCapSecs:    graceCapSecs,
	}
	claimsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("gateway ticket secret is required")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(claimsBytes); err != nil {
		return nil, err
	}
	ticket := &pb.SignedGatewayTicket{
		Alg:       "hmac-sha256",
		Claims:    claimsBytes,
		Signature: mac.Sum(nil),
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
}

func matchDomainAndGroup(token string, domains map[string]config.DomainConfig) (string, string, bool) {
	bestDomain := ""
	for domain := range domains {
		suffix := "." + domain
		if strings.HasSuffix(token, suffix) && len(domain) > len(bestDomain) {
			bestDomain = domain
		}
	}
	if bestDomain == "" {
		return "", "", false
	}
	group := strings.TrimSuffix(token, "."+bestDomain)
	group = strings.TrimSpace(group)
	if group == "" {
		return "", "", false
	}
	return bestDomain, group, true
}

func validateRegistrationRequest(reg *pb.RegistrationRequest) error {
	if reg.GetToken() == "" || len(reg.GetToken()) > 128 {
		return fmt.Errorf("token length error")
	}
	if reg.GetDeviceId() == "" || len(reg.GetDeviceId()) > 128 {
		return fmt.Errorf("device_id length error")
	}
	if reg.GetName() == "" || len(reg.GetName()) > 128 {
		return fmt.Errorf("name length error")
	}
	if len(reg.GetDevicePubKey()) == 0 {
		return fmt.Errorf("device_pub_key is empty")
	}
	if len(reg.GetOnlineKxPub()) != 32 {
		return fmt.Errorf("online_kx_pub length error")
	}
	return nil
}

func (c *Controller) buildServicePacket(request *protocol.Packet, appProto protocol.AppProtocol, msg proto.Message) (*protocol.Packet, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  appProto,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) newDeviceAuthChallenge(userID, groupName, deviceID, ticket string, devicePubKey []byte, reauthRequired bool) (*pb.DeviceAuthChallenge, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	challengeIDBytes := make([]byte, 16)
	if _, err := rand.Read(challengeIDBytes); err != nil {
		return nil, err
	}
	challengeID := fmt.Sprintf("%x", challengeIDBytes)
	challenge := deviceAuthChallengeState{
		UserID:         userID,
		GroupName:      groupName,
		DeviceID:       deviceID,
		Ticket:         ticket,
		DevicePubKey:   append([]byte(nil), devicePubKey...),
		Nonce:          nonce,
		ExpireAt:       time.Now().Add(deviceAuthChallengeTTL),
		ReauthRequired: reauthRequired,
	}
	c.authChallengeMu.Lock()
	defer c.authChallengeMu.Unlock()
	now := time.Now()
	for id, state := range c.authChallenges {
		if now.After(state.ExpireAt) {
			delete(c.authChallenges, id)
		}
	}
	c.authChallenges[challengeID] = challenge
	return &pb.DeviceAuthChallenge{
		ChallengeId:    challengeID,
		Nonce:          append([]byte(nil), nonce...),
		ExpireUnixMs:   challenge.ExpireAt.UnixMilli(),
		ReauthRequired: reauthRequired,
	}, nil
}

func (c *Controller) consumeDeviceAuthChallenge(challengeID string) (deviceAuthChallengeState, bool) {
	c.authChallengeMu.Lock()
	defer c.authChallengeMu.Unlock()
	challenge, ok := c.authChallenges[challengeID]
	if ok {
		delete(c.authChallenges, challengeID)
	}
	return challenge, ok
}

func buildDeviceAuthSignedPayload(challengeID string, nonce []byte, deviceID string, devicePubKey []byte) []byte {
	buf := make([]byte, 0, len(challengeID)+len(nonce)+len(deviceID)+len(devicePubKey)+16)
	appendLenPrefixed(&buf, []byte(challengeID))
	appendLenPrefixed(&buf, nonce)
	appendLenPrefixed(&buf, []byte(deviceID))
	appendLenPrefixed(&buf, devicePubKey)
	return buf
}

func appendLenPrefixed(buf *[]byte, data []byte) {
	var lenBuf [4]byte
	lenBuf[0] = byte(len(data) >> 24)
	lenBuf[1] = byte(len(data) >> 16)
	lenBuf[2] = byte(len(data) >> 8)
	lenBuf[3] = byte(len(data))
	*buf = append(*buf, lenBuf[:]...)
	*buf = append(*buf, data...)
}

func validateRequestedIP(virtualIP uint32, gateway net.IP, netmask net.IPMask) error {
	requested := util.Uint32ToIP(virtualIP)
	if gateway.Equal(requested) {
		return fmt.Errorf("client requested virtual ip is gateway ip")
	}
	networkIP := util.IpToUint32(gateway) & util.MaskToUint32(netmask)
	mask := util.MaskToUint32(netmask)
	broadcast := networkIP | ^mask
	first := networkIP + 1
	last := broadcast - 1
	if virtualIP < first || virtualIP > last {
		return fmt.Errorf("virtual ip %s out of network range", requested)
	}
	return nil
}

func (c *Controller) reservedServiceIPs(group string) map[uint32]string {
	reserved := make(map[uint32]string)
	if ip := strings.TrimSpace(c.resolveDNSServiceIP(group)); ip != "" {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			reserved[util.IpToUint32(parsed)] = "dns_service_ip"
		}
	}
	return reserved
}

func (c *Controller) resolveDNSServiceIP(group string) string {
	group = strings.ToLower(strings.TrimSpace(group))
	switch {
	case len(c.cfg.Domains) > 0:
		domainName, groupName, ok := matchDomainAndGroup(group, c.cfg.Domains)
		if !ok {
			return ""
		}
		gc := c.cfg.Domains[domainName].Groups[groupName]
		if strings.TrimSpace(gc.DNSServiceIP) != "" {
			return strings.TrimSpace(gc.DNSServiceIP)
		}
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	case len(c.cfg.Groups) > 0:
		gc, ok := c.cfg.Groups[group]
		if !ok {
			return ""
		}
		if strings.TrimSpace(gc.DNSServiceIP) != "" {
			return strings.TrimSpace(gc.DNSServiceIP)
		}
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	default:
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	}
}

func (c *Controller) clientOwnsVirtualIP(virtualIP uint32, deviceID string) bool {
	return c.clientOwnsVirtualIPInNetwork("", virtualIP, deviceID)
}

func (c *Controller) clientOwnsVirtualIPInNetwork(networkKey string, virtualIP uint32, deviceID string) bool {
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()
	for key, network := range c.nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		if client, ok := network.Clients[virtualIP]; ok {
			return client.DeviceId == deviceID
		}
	}
	return false
}

func buildDeviceInfoList(clients map[uint32]ClientInfo, selfIP uint32) []*pb.DeviceInfo {
	self, ok := clients[selfIP]
	if !ok {
		return nil
	}
	selfScope := clientNetworkScope(self, "")
	deviceList := make([]*pb.DeviceInfo, 0, len(clients))
	for ip, info := range clients {
		if ip == selfIP {
			continue
		}
		if clientNetworkScope(info, "") != selfScope {
			continue
		}
		item := &pb.DeviceInfo{
			Name:                 info.Name,
			VirtualIp:            ip,
			DeviceId:             info.DeviceId,
			DevicePubKey:         append([]byte(nil), info.DevicePubKey...),
			OnlineKxPub:          append([]byte(nil), info.OnlineKxPub...),
			PreferredChannelMode: info.PreferredChannelMode,
		}
		if info.ControlOnline {
			item.DeviceStatus = 0
		} else {
			item.DeviceStatus = 1
		}
		deviceList = append(deviceList, item)
	}
	return deviceList
}

func negotiateHandshakeCapabilities(requested []string) []string {
	if len(requested) == 0 {
		return nil
	}
	negotiated := make([]string, 0, len(requested))
	for _, capability := range requested {
		if _, ok := supportedHandshakeCapabilities[capability]; ok {
			negotiated = append(negotiated, capability)
		}
	}
	return negotiated
}

func (nc *NetworkControl) generateIP(
	network *NetworkInfo,
	requestedIP uint32,
	deviceID string,
	allowIPChange bool,
) (virtualIP uint32, oldIP uint32, err error) {
	oldIP = network.FindClientIPByDeviceID(deviceID)
	if requestedIP != 0 {
		if err = validateRequestedIP(requestedIP, network.Gateway, network.Netmask); err != nil {
			return 0, oldIP, err
		}
		if current, ok := network.Clients[requestedIP]; ok && current.DeviceId != deviceID {
			if !allowIPChange {
				return 0, oldIP, fmt.Errorf("virtual ip %s already in use", util.Uint32ToIP(requestedIP))
			}
			requestedIP = 0
		}
	}
	if requestedIP != 0 {
		return requestedIP, oldIP, nil
	}
	if oldIP != 0 {
		return oldIP, oldIP, nil
	}
	networkIP := util.IpToUint32(network.Gateway) & util.MaskToUint32(network.Netmask)
	mask := util.MaskToUint32(network.Netmask)
	broadcast := networkIP | ^mask
	gatewayIP := util.IpToUint32(network.Gateway)

	// first and last usable (exclude network and broadcast)
	first := networkIP + 1
	last := broadcast - 1
	if first > last {
		return 0, 0, fmt.Errorf("no available virtual ips")
	}
	for ip := first; ip <= last; ip++ {
		if ip == gatewayIP {
			continue
		}
		if _, reserved := network.ReservedIPs[ip]; reserved {
			continue
		}
		if client, occupied := network.Clients[ip]; occupied {
			if !client.ControlOnline {
				key := NewIpSessionKey(network.Group, util.Uint32ToIP(ip))
				if _, reserved := nc.IPSessions.Get(key); !reserved {
					network.DeleteClient(ip)
				} else {
					continue
				}
			} else {
				continue
			}
		}
		candidate := util.Uint32ToIP(ip)
		key := NewIpSessionKey(network.Group, candidate)
		if _, occupied := nc.IPSessions.Get(key); !occupied {
			addr := &net.IPAddr{IP: candidate}
			nc.IPSessions.Set(key, addr)
			return ip, 0, nil
		}
	}
	return 0, 0, fmt.Errorf("no available virtual ips")
}

func (nc *NetworkControl) TouchClientByIP(srcIP net.IP) uint16 {
	return nc.TouchClientByIPInNetwork("", srcIP)
}

func (nc *NetworkControl) TouchClientByIPInNetwork(networkKey string, srcIP net.IP) uint16 {
	ip := util.IpToUint32(srcIP)
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	now := time.Now().Unix()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		if client, ok := network.Clients[ip]; ok {
			client.ControlOnline = true
			client.ControlLastSeen = now
			network.UpsertClient(ip, client)
			return uint16(network.Epoch)
		}
	}
	return 0
}

func (c *Controller) TouchCipherSession(remoteAddr net.Addr) {
	c.nc.TouchCipherSession(remoteAddr)
}

func (nc *NetworkControl) TouchCipherSession(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	nc.CipherSessions.Set(remoteAddr.String(), struct{}{})
}

func (c *Controller) LeaveByRemoteAddr(remoteAddr net.Addr) {
	c.clearPendingHandshakeCapabilities(remoteAddr)
	c.nc.LeaveByRemoteAddr(remoteAddr)
}

func (nc *NetworkControl) LeaveByRemoteAddr(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	addr := remoteAddr.String()
	nc.CipherSessions.Delete(addr)
	now := time.Now().Unix()
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for _, network := range nc.VirtualNetwork.data {
		changed := false
		for ip, client := range network.Clients {
			if client.Address == nil || client.Address.String() != addr || !client.ControlOnline {
				continue
			}
			client.ControlOnline = false
			client.ControlLastSeen = now
			client.DataPlaneReachable = false
			client.DataPlaneLastSeen = 0
			client.ClientStatus = nil
			client.PreferredChannelMode = pb.ChannelMode_CHANNEL_MODE_AUTO
			network.UpsertClient(ip, client)
			nc.IPSessions.Set(NewIpSessionKey(network.Group, util.Uint32ToIP(ip)), remoteAddr)
			changed = true
		}
		if changed {
			network.Epoch++
		}
	}
}

func (nc *NetworkControl) DeviceListByIP(selfIP uint32) (*pb.DeviceList, bool) {
	return nc.DeviceListByIPInNetwork("", selfIP)
}

func (nc *NetworkControl) DeviceListByIPInNetwork(networkKey string, selfIP uint32) (*pb.DeviceList, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		if _, ok := network.Clients[selfIP]; !ok {
			continue
		}
		return &pb.DeviceList{
			Epoch:          uint32(network.Epoch),
			DeviceInfoList: buildDeviceInfoList(network.Clients, selfIP),
		}, true
	}
	return nil, false
}

func (nc *NetworkControl) FindClientByVirtualIP(virtualIP uint32) (ClientInfo, bool) {
	return nc.FindClientByVirtualIPInNetwork("", virtualIP)
}

func (nc *NetworkControl) FindClientByVirtualIPInNetwork(networkKey string, virtualIP uint32) (ClientInfo, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		client, ok := network.Clients[virtualIP]
		if ok {
			return client, true
		}
	}
	return ClientInfo{}, false
}

func (nc *NetworkControl) FindClientByDeviceID(groupName string, deviceID string) (ClientInfo, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	network, ok := nc.VirtualNetwork.data[groupName]
	if !ok {
		for _, network := range nc.VirtualNetwork.data {
			for _, client := range network.Clients {
				if client.DeviceId == deviceID && strings.EqualFold(clientAuthGroup(client, network.Group), groupName) {
					return client, true
				}
			}
		}
		return ClientInfo{}, false
	}
	virtualIP := network.FindClientIPByDeviceID(deviceID)
	if virtualIP != 0 {
		if client, ok := network.Clients[virtualIP]; ok {
			return client, true
		}
	}
	for _, client := range network.Clients {
		if client.DeviceId == deviceID {
			return client, true
		}
	}
	return ClientInfo{}, false
}

func (nc *NetworkControl) UpdateClientByVirtualIP(virtualIP uint32, update func(*ClientInfo)) bool {
	return nc.UpdateClientByVirtualIPInNetwork("", virtualIP, update)
}

func (nc *NetworkControl) UpdateClientByVirtualIPInNetwork(networkKey string, virtualIP uint32, update func(*ClientInfo)) bool {
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		client, ok := network.Clients[virtualIP]
		if !ok {
			continue
		}
		update(&client)
		network.UpsertClient(virtualIP, client)
		return true
	}
	return false
}

func (nc *NetworkControl) FindPunchSession(sessionID uint64, attempt uint32) (*PunchSession, bool) {
	return nc.PunchSessions.Get(punchSessionKey(sessionID, attempt))
}

// ExpireMap now accepts a key type K (must be comparable) and value type T.
type ExpireMap[K comparable, T any] struct {
	data       map[K]T
	expiration map[K]int64 // unixNano deadline per key; 0 means no expiry
	mutex      sync.RWMutex
	ttl        int64 // default ttl in nanoseconds; 0 means no default expiry
	stopCh     chan struct{}
}

// NewExpireMap creates an ExpireMap. defaultTTL == 0 means entries do not expire by default.
func NewExpireMap[K comparable, T any](defaultTTL time.Duration) *ExpireMap[K, T] {
	em := &ExpireMap[K, T]{
		data:       make(map[K]T),
		expiration: make(map[K]int64),
		ttl:        int64(defaultTTL),
		stopCh:     make(chan struct{}),
	}
	go em.janitor()
	return em
}

// Set stores value. Uses the map's default TTL provided in NewExpireMap; if default TTL == 0 the key does not expire.
func (e *ExpireMap[K, T]) Set(key K, value T) {
	var deadline int64
	if e.ttl > 0 {
		deadline = time.Now().Add(time.Duration(e.ttl)).UnixNano()
	} else {
		deadline = 0
	}

	e.mutex.Lock()
	e.data[key] = value
	if deadline == 0 {
		delete(e.expiration, key)
	} else {
		e.expiration[key] = deadline
	}
	e.mutex.Unlock()
}

// Get returns the value and true if present and not expired.
func (e *ExpireMap[K, T]) Get(key K) (T, bool) {
	e.mutex.RLock()
	deadline, hasExp := e.expiration[key]
	val, ok := e.data[key]
	e.mutex.RUnlock()

	if !ok {
		var zero T
		return zero, false
	}
	if hasExp && deadline > 0 && time.Now().UnixNano() > deadline {
		// expired; remove it
		e.mutex.Lock()
		delete(e.data, key)
		delete(e.expiration, key)
		e.mutex.Unlock()
		var zero T
		return zero, false
	}
	return val, true
}

// Delete removes a key immediately.
func (e *ExpireMap[K, T]) Delete(key K) {
	e.mutex.Lock()
	delete(e.data, key)
	delete(e.expiration, key)
	e.mutex.Unlock()
}

// Stop stops the janitor goroutine. After Stop, the map still usable but automatic cleanup stops.
func (e *ExpireMap[K, T]) Stop() {
	select {
	case <-e.stopCh:
		// already closed
	default:
		close(e.stopCh)
	}
}

// janitor periodically scans and removes expired entries.
func (e *ExpireMap[K, T]) janitor() {
	// choose a reasonable interval
	interval := time.Second
	if e.ttl > 0 {
		d := time.Duration(e.ttl) / 4
		if d > 0 && d < interval {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			e.mutex.Lock()
			for k, dl := range e.expiration {
				if dl > 0 && now > dl {
					delete(e.expiration, k)
					delete(e.data, k)
				}
			}
			e.mutex.Unlock()
		case <-e.stopCh:
			return
		}
	}
}
