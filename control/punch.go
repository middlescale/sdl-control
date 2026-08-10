package control

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

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
		P2PList:             make([]net.IP, 0, len(status.GetP2PList())),
		PublicUDPEndpoints:  make([]*net.UDPAddr, 0, len(status.GetPublicUdpEndpoints())),
		LocalUDPEndpoints:   make([]*net.UDPAddr, 0, len(status.GetLocalUdpEndpoints())),
		UpStream:            status.GetUpStream(),
		DownStream:          status.GetDownStream(),
		IsCone:              status.GetNatType() == pb.PunchNatType_Cone,
		PunchTriggerReason:  status.GetPunchTriggerReason().String(),
		RecoveryPunchTarget: status.GetRecoveryPunchTarget(),
		UpdateTime:          now,
		ExitNodeAdvertised:  status.GetExitNodeAdvertised(),
		ExitNodeLocalReady:  status.GetExitNodeLocalReady(),
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
		if client.ClientStatus == nil ||
			client.ClientStatus.ExitNodeAdvertised != clientStatus.ExitNodeAdvertised ||
			client.ClientStatus.ExitNodeLocalReady != clientStatus.ExitNodeLocalReady {
			changed = true
		}
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
	var packets []*protocol.Packet
	var buildErr error
	c.nc.forEachVirtualNetworkRead(networkKey, func(key string, network *NetworkInfo) bool {
		srcClient, ok := network.Clients[srcIP]
		if !ok || !srcClient.ControlOnline || srcClient.ClientStatus == nil {
			return true
		}
		triggerReason := pb.PunchTriggerReason_PunchTriggerStatusUpdate
		if parsed, ok := pb.PunchTriggerReason_value[srcClient.ClientStatus.PunchTriggerReason]; ok {
			triggerReason = pb.PunchTriggerReason(parsed)
		}
		recoveryPunchTarget := uint32(0)
		if triggerReason == pb.PunchTriggerReason_PunchTriggerManualRequest {
			recoveryPunchTarget = srcClient.ClientStatus.RecoveryPunchTarget
		}
		for targetIP, targetClient := range network.Clients {
			if targetIP == srcIP || !targetClient.ControlOnline || targetClient.ClientStatus == nil {
				continue
			}
			if recoveryPunchTarget != 0 && targetIP != recoveryPunchTarget {
				continue
			}
			if triggerReason == pb.PunchTriggerReason_StatusReportOnly {
				continue
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
			if manualTrigger {
				// Both endpoints can observe payload at the same time. Claim this
				// unordered pair atomically so their two recovery reports produce
				// one PunchStart session, while still allowing a quick retry.
				if !c.nc.ManualPunchPairDedup.TrySetIfAbsent(pairKey, struct{}{}) {
					continue
				}
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
				buildErr = fmt.Errorf("PunchStart source marshal error: %v", err)
				return false
			}
			targetPayload, err := proto.Marshal(targetStart)
			if err != nil {
				buildErr = fmt.Errorf("PunchStart target marshal error: %v", err)
				return false
			}
			packets = append(packets,
				&protocol.Packet{
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
				&protocol.Packet{
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
			)
			// A targeted recovery has found its one intended peer. Legacy manual
			// reports omit the target, so retain their fan-out behavior instead.
			if recoveryPunchTarget != 0 || !manualTrigger {
				return false
			}
		}
		return true
	})
	if buildErr != nil {
		return nil, buildErr
	}
	return packets, nil
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
	if clientsPreferRelay(srcClient, targetClient) {
		return true
	}
	return clientsHaveAnyP2PPath(srcClient, srcIP, targetClient, targetIP)
}

func shouldSuppressPunchStartForOtherTrigger(
	srcClient ClientInfo,
	srcIP uint32,
	targetClient ClientInfo,
	targetIP uint32,
) bool {
	if clientsPreferRelay(srcClient, targetClient) {
		return true
	}
	return clientsHaveMutualP2PPath(srcClient, srcIP, targetClient, targetIP)
}

func clientsPreferRelay(srcClient ClientInfo, targetClient ClientInfo) bool {
	return srcClient.PreferredChannelMode == pb.ChannelMode_CHANNEL_MODE_RELAY ||
		targetClient.PreferredChannelMode == pb.ChannelMode_CHANNEL_MODE_RELAY
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
	sourceClient, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, sourceIP)
	if !ok {
		return nil, fmt.Errorf("punch source %s not registered", util.Uint32ToIP(sourceIP))
	}
	targetClient, ok := c.nc.FindClientByVirtualIPInNetwork(networkKey, req.GetTarget())
	if !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	if clientsPreferRelay(sourceClient, targetClient) {
		return nil, nil
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
