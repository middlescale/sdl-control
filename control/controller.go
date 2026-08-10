package control

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"net"
	"os"
	"sdl-control/config"
	"sdl-control/control/store"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
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

	exitNodeMu       sync.RWMutex
	exitNodeApproved map[string]map[string]bool

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

type ExitNodeAdminView struct {
	UserID             string `json:"user_id"`
	Group              string `json:"group,omitempty"`
	Name               string `json:"name,omitempty"`
	DeviceID           string `json:"device_id"`
	VirtualIP          string `json:"virtual_ip,omitempty"`
	Approved           bool   `json:"approved"`
	Advertised         bool   `json:"advertised"`
	LocalReady         bool   `json:"local_ready"`
	Usable             bool   `json:"usable"`
	ControlOnline      bool   `json:"control_online"`
	DataPlaneReachable bool   `json:"data_plane_reachable"`
	UpdatedAtUnix      int64  `json:"updated_at_unix,omitempty"`
}

const maxPunchAttemptsPerPair = 3
const manualPunchPairDedupWindow = 3 * time.Second
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
	exitNodeApproved, err := newExitNodeApprovalStateFromStore(pgStore)
	if err != nil {
		return nil, err
	}
	return &Controller{
		pgStore: pgStore,
		nc: NetworkControl{
			VirtualNetwork:       *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IPSessions:           *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
			CipherSessions:       *NewExpireMap[string, struct{}](24 * time.Hour),
			PunchSessions:        *NewExpireMap[string, *PunchSession](10 * time.Minute),
			PunchPairCooldown:    *NewExpireMap[string, struct{}](20 * time.Second),
			ManualPunchPairDedup: *NewExpireMap[string, struct{}](manualPunchPairDedupWindow),
			PunchPairRetry:       *NewExpireMap[string, PunchRetryState](30 * time.Minute),
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
		exitNodeApproved:         exitNodeApproved,
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

func newExitNodeApprovalStateFromStore(pgStore *store.Store) (map[string]map[string]bool, error) {
	if pgStore != nil {
		approved, err := loadExitNodeApprovalStateFromPostgres(pgStore)
		if err != nil {
			return nil, fmt.Errorf("load exit-node approval store from postgres: %w", err)
		}
		return approved, nil
	}
	return map[string]map[string]bool{}, nil
}

func loadExitNodeApprovalStateFromPostgres(pgStore *store.Store) (map[string]map[string]bool, error) {
	records, err := pgStore.ListActiveExitNodeApprovals()
	if err != nil {
		return nil, err
	}
	approved := make(map[string]map[string]bool)
	for _, record := range records {
		userID := strings.TrimSpace(record.UserID)
		deviceID := strings.TrimSpace(record.DeviceID)
		if userID == "" || deviceID == "" {
			continue
		}
		if approved[userID] == nil {
			approved[userID] = map[string]bool{}
		}
		approved[userID][deviceID] = true
	}
	return approved, nil
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

func (c *Controller) PgStore() *store.Store {
	return c.pgStore
}

func (c *Controller) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IPSessions.Stop()
	c.nc.CipherSessions.Stop()
	c.nc.PunchSessions.Stop()
	c.nc.PunchPairCooldown.Stop()
	c.nc.ManualPunchPairDedup.Stop()
	c.nc.PunchPairRetry.Stop()
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
			ExitNodeAdvertised:   clientExitNodeAdvertised(info),
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
