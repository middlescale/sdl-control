package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"sdl-control/config"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
)

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
