package control

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
)

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

	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()

	netInfo, netInfoExist := c.nc.VirtualNetwork.data[networkIdentity.Key()]
	if !netInfoExist {
		netInfo = NewNetworkInfo(networkIdentity.Key(), netmask, net.IP(gateway), c.reservedServiceIPs(authGroup))
		c.nc.VirtualNetwork.data[networkIdentity.Key()] = netInfo
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
	c.enrichDeviceInfoListExitNodesFromClients(registrationResp.DeviceInfoList, netInfo.Clients)

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
	renameReason := ""
	c.nc.forEachVirtualNetworkRead(request.RouteNetworkKey, func(_ string, network *NetworkInfo) bool {
		client, ok := network.Clients[srcIP]
		if !ok {
			return true
		}
		if client.DeviceId != deviceID {
			renameReason = "device mismatch"
			return false
		}
		if c.networkHasDuplicateDeviceNameLocked(network, deviceID, newName) {
			renameReason = "device name already exists"
			return false
		}
		groupName = clientAuthGroup(client, network.Group)
		return false
	})
	if renameReason != "" {
		resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    renameReason,
		})
		return resp, 0, err
	}
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
	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()

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

	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()
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
	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()
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
		c.enrichDeviceInfoListExitNodes(routeNetworkKey, deviceList.DeviceInfoList)
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

func (c *Controller) BuildPushDeviceListPacketsForAuthedDeviceChange(userID, deviceID string) ([]*protocol.Packet, error) {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	if userID == "" || deviceID == "" {
		return nil, nil
	}
	var selectedIP uint32
	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
		for _, client := range network.Clients {
			if client.UserID != userID || client.DeviceId != deviceID || !client.ControlOnline {
				continue
			}
			selectedIP = client.VirtualIp
			return false
		}
		return true
	})
	if selectedIP != 0 {
		return c.BuildPushDeviceListPacketsForPeerChange(selectedIP)
	}
	return nil, nil
}

func (c *Controller) BuildPushDeviceListPacketsForPeerChangeInNetwork(networkKey string, changedIP uint32) ([]*protocol.Packet, error) {
	var packets []*protocol.Packet
	var buildErr error
	found := false
	c.nc.forEachVirtualNetworkRead(networkKey, func(_ string, network *NetworkInfo) bool {
		changedClient, ok := network.Clients[changedIP]
		if !ok {
			return true
		}
		found = true
		if !changedClient.ControlOnline {
			return false
		}
		changedScope := clientNetworkScope(changedClient, network.Group)
		packets = make([]*protocol.Packet, 0, len(network.Clients))
		for targetIP, targetClient := range network.Clients {
			if targetIP == changedIP || !targetClient.ControlOnline {
				continue
			}
			if clientNetworkScope(targetClient, network.Group) != changedScope {
				continue
			}
			targetNetworkKey := clientNetworkKey(targetClient, network.Group)
			gatewayGrants, gatewayPolicyRev := c.buildGatewayAccessGrantsForExistingClient(targetNetworkKey, targetIP, targetClient.DeviceId)
			deviceInfoList := buildDeviceInfoList(network.Clients, targetIP)
			c.enrichDeviceInfoListExitNodesFromClients(deviceInfoList, network.Clients)
			packet, err := c.buildPushDeviceListPacket(
				targetNetworkKey,
				targetIP,
				uint32(network.Epoch),
				deviceInfoList,
				gatewayGrants,
				gatewayPolicyRev,
			)
			if err != nil {
				buildErr = err
				return false
			}
			packets = append(packets, packet)
		}
		return false
	})
	if buildErr != nil {
		return nil, buildErr
	}
	if found {
		return packets, nil
	}
	return nil, nil
}

func (c *Controller) BuildPushDeviceListPacketsForGatewayChange() ([]*protocol.Packet, error) {
	var packets []*protocol.Packet
	var buildErr error
	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
		for targetIP, targetClient := range network.Clients {
			if !targetClient.ControlOnline {
				continue
			}
			targetNetworkKey := clientNetworkKey(targetClient, network.Group)
			gatewayGrants, gatewayPolicyRev := c.buildGatewayAccessGrantsForExistingClient(targetNetworkKey, targetIP, targetClient.DeviceId)
			deviceInfoList := buildDeviceInfoList(network.Clients, targetIP)
			c.enrichDeviceInfoListExitNodesFromClients(deviceInfoList, network.Clients)
			packet, err := c.buildPushDeviceListPacket(
				targetNetworkKey,
				targetIP,
				uint32(network.Epoch),
				deviceInfoList,
				gatewayGrants,
				gatewayPolicyRev,
			)
			if err != nil {
				buildErr = err
				return false
			}
			packets = append(packets, packet)
		}
		return true
	})
	if buildErr != nil {
		return nil, buildErr
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
