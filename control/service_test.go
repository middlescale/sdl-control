package control

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"sdl-control/config"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

const testGatewayTicketSecret = "test-gateway-ticket-secret"

func TestHandleHandshakePacketSuccess(t *testing.T) {
	cfg := &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}
	ctrl := newControllerWithConfig(t, cfg)
	defer ctrl.Stop()

	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"udp_endpoint_report_v1", "punch_coord_v1", "gateway_ticket_v1", "unknown_cap"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	srcIP := net.ParseIP("10.26.0.2")
	reqPacket := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    srcIP,
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}

	respPacket, err := ctrl.HandleHandshakePacket(reqPacket, remoteAddr)
	if err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}
	if respPacket.Ver != protocol.V3 {
		t.Fatalf("unexpected version: %v", respPacket.Ver)
	}
	if respPacket.Proto != protocol.ProtocolService {
		t.Fatalf("unexpected proto: %v", respPacket.Proto)
	}
	if respPacket.AppProto != protocol.AppProtoHandshakeResponse {
		t.Fatalf("unexpected app proto: %v", respPacket.AppProto)
	}
	if respPacket.SourceTTL != protocol.MAX_TTL {
		t.Fatalf("unexpected source ttl: %v", respPacket.SourceTTL)
	}
	if respPacket.TTL != protocol.MAX_TTL {
		t.Fatalf("unexpected ttl: %v", respPacket.TTL)
	}
	if !respPacket.SrcIP.Equal(reqPacket.DstIP) {
		t.Fatalf("unexpected source ip: %v", respPacket.SrcIP)
	}
	if !respPacket.DstIP.Equal(srcIP) {
		t.Fatalf("unexpected destination ip: %v", respPacket.DstIP)
	}

	var resp pb.HandshakeResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal handshake response failed: %v", err)
	}
	if resp.GetVersion() != "goversion-1.0.0" {
		t.Fatalf("unexpected response version: %s", resp.GetVersion())
	}
	if len(resp.GetCapabilities()) != 3 || resp.GetCapabilities()[0] != "udp_endpoint_report_v1" || resp.GetCapabilities()[1] != "punch_coord_v1" || resp.GetCapabilities()[2] != "gateway_ticket_v1" {
		t.Fatalf("unexpected capabilities: %v", resp.GetCapabilities())
	}
}

func TestHandleHandshakePacketInvalidPayload(t *testing.T) {
	cfg := &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}
	ctrl := newControllerWithConfig(t, cfg)
	defer ctrl.Stop()

	reqPacket := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		Payload:  []byte{0x01, 0x02},
	}

	if _, err := ctrl.HandleHandshakePacket(reqPacket, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}); err == nil {
		t.Fatalf("expected error for invalid payload")
	}
}

func TestHandleHandshakePacketUnsupportedCapabilities(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"unknown_cap_a", "unknown_cap_b"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	respPacket, err := ctrl.HandleHandshakePacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	if err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}
	var resp pb.HandshakeResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal handshake response failed: %v", err)
	}
	if len(resp.GetCapabilities()) != 0 {
		t.Fatalf("expected empty negotiated capabilities, got: %v", resp.GetCapabilities())
	}
}

func TestRegistrationPersistsNegotiatedCapabilities(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.10"), Port: 1111}
	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"udp_endpoint_report_v1", "punch_coord_v1", "unknown_cap"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	if _, err := ctrl.HandleHandshakePacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}, remoteAddr); err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}

	regReq := newBaseRegisterReq("dev-cap-a", "node-cap-a")
	ensureAuthed(t, ctrl, regReq.GetToken(), regReq.GetDeviceId(), regReq.GetDevicePubKey())
	respPacket, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, regReq), remoteAddr)
	if err != nil {
		t.Fatalf("HandleRegistrationPacket failed: %v", err)
	}
	var regResp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &regResp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	netInfo, ok := ctrl.nc.VirtualNetwork.Get(regReq.GetToken())
	if !ok {
		t.Fatalf("expected network info for %s", regReq.GetToken())
	}
	clientInfo, ok := netInfo.Clients[regResp.GetVirtualIp()]
	if !ok {
		t.Fatalf("expected client info for virtual ip %v", util.Uint32ToIP(regResp.GetVirtualIp()))
	}
	if len(clientInfo.Capabilities) != 2 || clientInfo.Capabilities[0] != "udp_endpoint_report_v1" || clientInfo.Capabilities[1] != "punch_coord_v1" {
		t.Fatalf("unexpected client capabilities: %+v", clientInfo.Capabilities)
	}
}

func TestRegistrationAllowsMissingUDPEndpointReportCapability(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.11"), Port: 1112}
	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"punch_coord_v1"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	if _, err := ctrl.HandleHandshakePacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}, remoteAddr); err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}

	regReq := newBaseRegisterReq("dev-cap-bad", "node-cap-bad")
	ensureAuthed(t, ctrl, regReq.GetToken(), regReq.GetDeviceId(), regReq.GetDevicePubKey())
	respPacket, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, regReq), remoteAddr)
	if err != nil {
		t.Fatalf("expected registration to proceed without udp_endpoint_report_v1, got %v", err)
	}
	var regResp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &regResp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	netInfo, ok := ctrl.nc.VirtualNetwork.Get(regReq.GetToken())
	if !ok {
		t.Fatalf("expected network info for %s", regReq.GetToken())
	}
	clientInfo, ok := netInfo.Clients[regResp.GetVirtualIp()]
	if !ok {
		t.Fatalf("expected client info for virtual ip %v", util.Uint32ToIP(regResp.GetVirtualIp()))
	}
	if len(clientInfo.Capabilities) != 1 || clientInfo.Capabilities[0] != "punch_coord_v1" {
		t.Fatalf("expected negotiated capabilities to be preserved, got %+v", clientInfo.Capabilities)
	}
}

func TestRegistrationRetryReusesHandshakeCapabilitiesForSameRemote(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.12"), Port: 1113}
	handshakeRemote(t, ctrl, remoteAddr)

	regReq1 := newBaseRegisterReq("dev-cap-retry-a", "node-cap-retry-a")
	ensureAuthed(t, ctrl, regReq1.GetToken(), regReq1.GetDeviceId(), regReq1.GetDevicePubKey())
	if _, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, regReq1), remoteAddr); err != nil {
		t.Fatalf("first HandleRegistrationPacket failed: %v", err)
	}

	regReq2 := newBaseRegisterReq("dev-cap-retry-b", "node-cap-retry-b")
	ensureAuthed(t, ctrl, regReq2.GetToken(), regReq2.GetDeviceId(), regReq2.GetDevicePubKey())
	if _, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, regReq2), remoteAddr); err != nil {
		t.Fatalf("second HandleRegistrationPacket should reuse handshake capabilities, got %v", err)
	}
}

func TestRegistrationWithExplicitCapabilitiesAllowsSessionScopedHandshakeState(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	regReq := newBaseRegisterReq("dev-cap-host-fallback", "node-cap-host-fallback")
	ensureAuthed(t, ctrl, regReq.GetToken(), regReq.GetDeviceId(), regReq.GetDevicePubKey())
	registrationRemote := &net.UDPAddr{IP: net.ParseIP("1.1.1.12"), Port: 1113}
	if _, _, _, err := ctrl.HandleRegistrationPacketWithVirtualIPAndCapabilities(
		newRegistrationPacket(t, regReq),
		registrationRemote,
		[]string{capabilityUDPEndpointReportV1, "punch_coord_v1"},
	); err != nil {
		t.Fatalf("HandleRegistrationPacketWithVirtualIPAndCapabilities should accept explicit session capabilities, got %v", err)
	}
}

func TestPunchCoordProtoContractRoundTrip(t *testing.T) {
	req := &pb.PunchRequest{
		SessionId:     1001,
		Source:        util.IpToUint32(net.ParseIP("10.26.0.2")),
		Target:        util.IpToUint32(net.ParseIP("10.26.0.3")),
		SourceNatType: pb.PunchNatType_Cone,
		TargetNatType: pb.PunchNatType_Symmetric,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("1.1.1.1")), Port: 5000, Tcp: false},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("2.2.2.2")), Port: 6000, Tcp: false},
		},
		Attempt:                 1,
		TimeoutMs:               2000,
		DeadlineUnixMs:          10000,
		TriggerReason:           pb.PunchTriggerReason_PunchTriggerManualRequest,
		AttemptBudget:           3,
		EndpointSelectionPolicy: pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll,
	}
	buf, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	var decoded pb.PunchRequest
	if err := proto.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal punch request failed: %v", err)
	}
	if decoded.GetSessionId() != req.GetSessionId() || decoded.GetAttempt() != req.GetAttempt() || decoded.GetTimeoutMs() != req.GetTimeoutMs() || decoded.GetDeadlineUnixMs() != req.GetDeadlineUnixMs() || len(decoded.GetSourceEndpoints()) != 1 || len(decoded.GetTargetEndpoints()) != 1 {
		t.Fatalf("unexpected decoded punch request: %+v", decoded)
	}
	if decoded.GetSourceNatType() != pb.PunchNatType_Cone || decoded.GetTargetNatType() != pb.PunchNatType_Symmetric {
		t.Fatalf("unexpected decoded nat types: source=%v target=%v", decoded.GetSourceNatType(), decoded.GetTargetNatType())
	}
	if decoded.GetTriggerReason() != pb.PunchTriggerReason_PunchTriggerManualRequest || decoded.GetAttemptBudget() != 3 || decoded.GetEndpointSelectionPolicy() != pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll {
		t.Fatalf("unexpected decoded punch semantics: %+v", decoded)
	}
	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    req.GetTarget(),
		Attempt:   req.GetAttempt(),
		Accepted:  true,
		Phase:     pb.PunchSessionPhase_PunchPhaseSending,
	}
	ackBuf, err := proto.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	var ackDecoded pb.PunchAck
	if err := proto.Unmarshal(ackBuf, &ackDecoded); err != nil {
		t.Fatalf("unmarshal punch ack failed: %v", err)
	}
	if !ackDecoded.GetAccepted() || ackDecoded.GetSessionId() != req.GetSessionId() || ackDecoded.GetAttempt() != req.GetAttempt() || ackDecoded.GetPhase() != pb.PunchSessionPhase_PunchPhaseSending {
		t.Fatalf("unexpected decoded punch ack: %+v", ackDecoded)
	}
	result := &pb.PunchResult{
		SessionId: req.GetSessionId(),
		Source:    req.GetSource(),
		Target:    req.GetTarget(),
		Attempt:   req.GetAttempt(),
		Code:      pb.PunchResultCode(99),
		Reason:    "compat-enum",
		Phase:     pb.PunchSessionPhase_PunchPhaseFailed,
		SelectedEndpoint: &pb.PunchEndpoint{
			Ip:   req.GetSourceEndpoints()[0].GetIp(),
			Port: req.GetSourceEndpoints()[0].GetPort(),
		},
	}
	resultBuf, err := proto.Marshal(result)
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	var resultDecoded pb.PunchResult
	if err := proto.Unmarshal(resultBuf, &resultDecoded); err != nil {
		t.Fatalf("unmarshal punch result failed: %v", err)
	}
	if resultDecoded.GetCode() != pb.PunchResultCode(99) || resultDecoded.GetPhase() != pb.PunchSessionPhase_PunchPhaseFailed || resultDecoded.GetSelectedEndpoint() == nil || resultDecoded.GetSelectedEndpoint().GetPort() != req.GetSourceEndpoints()[0].GetPort() {
		t.Fatalf("unexpected decoded punch result: %+v", resultDecoded)
	}
}

func TestPunchSessionLifecycleHandlers(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &pb.PunchRequest{
		SessionId:               2001,
		Source:                  srcReg.GetVirtualIp(),
		Target:                  dstReg.GetVirtualIp(),
		Attempt:                 1,
		AttemptBudget:           3,
		TriggerReason:           pb.PunchTriggerReason_PunchTriggerManualRequest,
		EndpointSelectionPolicy: pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	reqPayload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	resp, err := ctrl.HandlePunchRequestPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchRequest,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Payload:  reqPayload,
	})
	if err != nil {
		t.Fatalf("HandlePunchRequestPacket failed: %v", err)
	}
	if resp.AppProto != protocol.AppProtoPunchAck {
		t.Fatalf("unexpected punch request response app proto: %v", resp.AppProto)
	}
	session, ok := ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionScheduled {
		t.Fatalf("unexpected session after request: %+v", session)
	}

	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    dstReg.GetVirtualIp(),
		Attempt:   req.GetAttempt(),
		Accepted:  true,
		Phase:     pb.PunchSessionPhase_PunchPhaseSending,
	}
	ackPayload, err := proto.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	if err := ctrl.HandlePunchAckPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchAck,
		SrcIP:    util.Uint32ToIP(dstReg.GetVirtualIp()),
		Payload:  ackPayload,
	}); err != nil {
		t.Fatalf("HandlePunchAckPacket failed: %v", err)
	}
	session, ok = ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionWaiting {
		t.Fatalf("unexpected session after ack: %+v", session)
	}

	result := &pb.PunchResult{
		SessionId: req.GetSessionId(),
		Source:    dstReg.GetVirtualIp(),
		Target:    srcReg.GetVirtualIp(),
		Attempt:   req.GetAttempt(),
		Code:      pb.PunchResultCode_PunchResultSuccess,
		Reason:    "ok",
		Phase:     pb.PunchSessionPhase_PunchPhaseSuccess,
	}
	resultPayload, err := proto.Marshal(result)
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	if err := ctrl.HandlePunchResultPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchResult,
		SrcIP:    util.Uint32ToIP(dstReg.GetVirtualIp()),
		Payload:  resultPayload,
	}); err != nil {
		t.Fatalf("HandlePunchResultPacket failed: %v", err)
	}
	session, ok = ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionSuccess {
		t.Fatalf("unexpected session after result: %+v", session)
	}
	if session.RelayFallback {
		t.Fatalf("success session should not require relay fallback")
	}
}

func TestPunchLogHelpers(t *testing.T) {
	source := util.IpToUint32(net.ParseIP("10.26.0.2"))
	target := util.IpToUint32(net.ParseIP("10.26.0.3"))
	session := &PunchSession{Source: source, Target: target}

	if peer := punchPeerIP(session, source); peer != target {
		t.Fatalf("unexpected source peer: %s", util.Uint32ToIP(peer))
	}
	if peer := punchPeerIP(session, target); peer != source {
		t.Fatalf("unexpected target peer: %s", util.Uint32ToIP(peer))
	}
	if peer := punchPeerIP(session, util.IpToUint32(net.ParseIP("10.26.0.9"))); peer != 0 {
		t.Fatalf("unexpected unknown peer: %d", peer)
	}

	if got := formatPunchEndpoint(nil); got != "-" {
		t.Fatalf("unexpected nil endpoint format: %q", got)
	}
	if got := formatPunchEndpoint(&pb.PunchEndpoint{
		Ip:   util.IpToUint32(net.ParseIP("1.2.3.4")),
		Port: 51820,
	}); got != "1.2.3.4:51820/udp" {
		t.Fatalf("unexpected ipv4 endpoint format: %q", got)
	}
	if got := formatPunchEndpoint(&pb.PunchEndpoint{
		Ipv6: net.ParseIP("2001:db8::1"),
		Port: 443,
		Tcp:  true,
	}); got != "[2001:db8::1]:443/tcp" {
		t.Fatalf("unexpected ipv6 endpoint format: %q", got)
	}
}

func TestBuildPunchStartPackets(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &pb.PunchRequest{
		SessionId: 3001,
		Source:    srcReg.GetVirtualIp(),
		Target:    dstReg.GetVirtualIp(),
		Attempt:   1,
		TimeoutMs: 2500,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 3333},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 4444},
		},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	packets, err := ctrl.BuildPunchStartPackets(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchRequest,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPackets failed: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("expected 2 punch start packets, got %d", len(packets))
	}
	first := packets[0]
	if first.AppProto != protocol.AppProtoPunchStart || !first.DstIP.Equal(util.Uint32ToIP(srcReg.GetVirtualIp())) {
		t.Fatalf("unexpected first punch start packet: %+v", first)
	}
	second := packets[1]
	if second.AppProto != protocol.AppProtoPunchStart || !second.DstIP.Equal(util.Uint32ToIP(dstReg.GetVirtualIp())) {
		t.Fatalf("unexpected second punch start packet: %+v", second)
	}
}

func TestBuildPunchStartPacketsSkipsForcedRelayClient(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	status := &pb.ClientStatusInfo{
		Source:               srcReg.GetVirtualIp(),
		PreferredChannelMode: pb.ChannelMode_CHANNEL_MODE_RELAY,
	}
	statusPayload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		Payload:  statusPayload,
	}); err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}
	req := &pb.PunchRequest{
		SessionId: 3001,
		Source:    srcReg.GetVirtualIp(),
		Target:    dstReg.GetVirtualIp(),
		Attempt:   1,
		TimeoutMs: 2500,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 3333},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 4444},
		},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	packets, err := ctrl.BuildPunchStartPackets(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchRequest,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPackets failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected forced relay client to suppress punch start, got %d packets", len(packets))
	}
}

func TestHandlePunchAckAndResultInitializeSessionMaps(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	srcIP := util.IpToUint32(net.ParseIP("10.26.0.2"))
	dstIP := util.IpToUint32(net.ParseIP("10.26.0.3"))
	sessionID := uint64(4001)
	attempt := uint32(1)
	key := punchSessionKey(sessionID, attempt)
	ctrl.nc.PunchSessions.Set(key, &PunchSession{
		SessionID:      sessionID,
		Source:         srcIP,
		Target:         dstIP,
		Attempt:        attempt,
		DeadlineUnixMs: time.Now().Add(5 * time.Second).UnixMilli(),
		State:          PunchSessionScheduled,
		RequestedAt:    time.Now().Unix(),
	})

	ackPayload, err := proto.Marshal(&pb.PunchAck{
		SessionId: sessionID,
		Source:    dstIP,
		Attempt:   attempt,
		Accepted:  true,
		Phase:     pb.PunchSessionPhase_PunchPhaseSending,
	})
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	if err := ctrl.HandlePunchAckPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchAck,
		SrcIP:    util.Uint32ToIP(dstIP),
		Payload:  ackPayload,
	}); err != nil {
		t.Fatalf("HandlePunchAckPacket failed: %v", err)
	}

	resultPayload, err := proto.Marshal(&pb.PunchResult{
		SessionId: sessionID,
		Source:    dstIP,
		Target:    srcIP,
		Attempt:   attempt,
		Code:      pb.PunchResultCode_PunchResultSuccess,
		Reason:    "ok",
		Phase:     pb.PunchSessionPhase_PunchPhaseSuccess,
	})
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	if err := ctrl.HandlePunchResultPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchResult,
		SrcIP:    util.Uint32ToIP(dstIP),
		Payload:  resultPayload,
	}); err != nil {
		t.Fatalf("HandlePunchResultPacket failed: %v", err)
	}

	session, ok := ctrl.nc.FindPunchSession(sessionID, attempt)
	if !ok {
		t.Fatalf("session not found")
	}
	if session.Ack == nil || session.Results == nil {
		t.Fatalf("session maps not initialized: %+v", session)
	}
	if !session.Ack[dstIP] {
		t.Fatalf("ack not recorded for %d", dstIP)
	}
	if session.Results[dstIP] == nil {
		t.Fatalf("result not recorded for %d", dstIP)
	}
}

func TestBuildPunchStartPacketsFromStatus(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:             srcReg.GetVirtualIp(),
		NatType:            pb.PunchNatType_Cone,
		PunchTriggerReason: pb.PunchTriggerReason_PunchTriggerRouteTimeout,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 2 {
		t.Fatalf("expected 2 start packets, got %d", len(startPackets))
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	if start.GetTriggerReason() != pb.PunchTriggerReason_PunchTriggerRouteTimeout || start.GetAttemptBudget() != 3 || start.GetEndpointSelectionPolicy() != pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll {
		t.Fatalf("unexpected punch start semantics: %+v", start)
	}
	var foundPublic, foundLocal bool
	for _, ep := range start.GetPeerEndpoints() {
		switch {
		case ep.GetIp() == util.IpToUint32(net.ParseIP("9.9.9.9")) && ep.GetPort() == 30002:
			foundPublic = true
		case ep.GetIp() == util.IpToUint32(net.ParseIP("1.1.1.2")) && ep.GetPort() == 2222:
			foundLocal = true
		}
	}
	if !foundPublic {
		t.Fatalf("expected public endpoint in punch start, got %+v", start.GetPeerEndpoints())
	}
	if foundLocal {
		t.Fatalf("unexpected local endpoint for public remote address: %+v", start.GetPeerEndpoints())
	}
	next, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("second BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(next) != 0 {
		t.Fatalf("expected cooldown to suppress immediate re-trigger, got %d packets", len(next))
	}
}

func TestBuildPunchStartPacketsFromStatusTargetsRecoveryPeer(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	targetReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	otherReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-c", "node-c"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})

	statuses := []struct {
		registration *pb.RegistrationResponse
		status       *pb.ClientStatusInfo
	}{
		{
			registration: srcReg,
			status: &pb.ClientStatusInfo{
				Source:              srcReg.GetVirtualIp(),
				NatType:             pb.PunchNatType_Cone,
				PunchTriggerReason:  pb.PunchTriggerReason_PunchTriggerManualRequest,
				RecoveryPunchTarget: targetReg.GetVirtualIp(),
				PublicUdpEndpoints:  []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001}},
			},
		},
		{
			registration: targetReg,
			status: &pb.ClientStatusInfo{
				Source:             targetReg.GetVirtualIp(),
				NatType:            pb.PunchNatType_Cone,
				PublicUdpEndpoints: []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002}},
			},
		},
		{
			registration: otherReg,
			status: &pb.ClientStatusInfo{
				Source:             otherReg.GetVirtualIp(),
				NatType:            pb.PunchNatType_Cone,
				PublicUdpEndpoints: []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("7.7.7.7")), Port: 30003}},
			},
		},
	}
	for _, entry := range statuses {
		payload, err := proto.Marshal(entry.status)
		if err != nil {
			t.Fatalf("marshal client status failed: %v", err)
		}
		if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
			Proto:    protocol.ProtocolService,
			AppProto: protocol.AppProtoClientStatusInfo,
			SrcIP:    util.Uint32ToIP(entry.registration.GetVirtualIp()),
			Payload:  payload,
		}); err != nil {
			t.Fatalf("update client status failed: %v", err)
		}
	}

	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("expected exactly the source/target punch pair, got %d packets", len(packets))
	}
	for _, packet := range packets {
		if packet.DstIP.Equal(util.Uint32ToIP(otherReg.GetVirtualIp())) {
			t.Fatalf("recovery punch incorrectly selected unrelated peer %s", packet.DstIP)
		}
		if !packet.DstIP.Equal(util.Uint32ToIP(srcReg.GetVirtualIp())) && !packet.DstIP.Equal(util.Uint32ToIP(targetReg.GetVirtualIp())) {
			t.Fatalf("unexpected recovery punch destination %s", packet.DstIP)
		}
	}
}

func TestBuildPunchStartPacketsFromStatusManualRecoveryWithoutTargetFansOut(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	firstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	secondReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-c", "node-c"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})

	statuses := []struct {
		registration *pb.RegistrationResponse
		status       *pb.ClientStatusInfo
	}{
		{
			registration: srcReg,
			status: &pb.ClientStatusInfo{
				Source:             srcReg.GetVirtualIp(),
				NatType:            pb.PunchNatType_Cone,
				PunchTriggerReason: pb.PunchTriggerReason_PunchTriggerManualRequest,
				PublicUdpEndpoints: []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001}},
			},
		},
		{
			registration: firstReg,
			status: &pb.ClientStatusInfo{
				Source:             firstReg.GetVirtualIp(),
				NatType:            pb.PunchNatType_Cone,
				PublicUdpEndpoints: []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002}},
			},
		},
		{
			registration: secondReg,
			status: &pb.ClientStatusInfo{
				Source:             secondReg.GetVirtualIp(),
				NatType:            pb.PunchNatType_Cone,
				PublicUdpEndpoints: []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("7.7.7.7")), Port: 30003}},
			},
		},
	}
	for _, entry := range statuses {
		payload, err := proto.Marshal(entry.status)
		if err != nil {
			t.Fatalf("marshal client status failed: %v", err)
		}
		if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
			Proto:    protocol.ProtocolService,
			AppProto: protocol.AppProtoClientStatusInfo,
			SrcIP:    util.Uint32ToIP(entry.registration.GetVirtualIp()),
			Payload:  payload,
		}); err != nil {
			t.Fatalf("update client status failed: %v", err)
		}
	}

	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 4 {
		t.Fatalf("manual recovery without a target must fan out to both peers, got %d packets", len(packets))
	}
}

func TestBuildPunchStartPacketsFromStatusDeduplicatesBidirectionalManualRecovery(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	firstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	secondReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	reportStatus := func(reg *pb.RegistrationResponse, target uint32) {
		payload, err := proto.Marshal(&pb.ClientStatusInfo{
			Source:              reg.GetVirtualIp(),
			NatType:             pb.PunchNatType_Cone,
			PunchTriggerReason:  pb.PunchTriggerReason_PunchTriggerManualRequest,
			RecoveryPunchTarget: target,
			PublicUdpEndpoints:  []*pb.PunchEndpoint{{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001}},
		})
		if err != nil {
			t.Fatalf("marshal client status failed: %v", err)
		}
		if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
			Proto:    protocol.ProtocolService,
			AppProto: protocol.AppProtoClientStatusInfo,
			SrcIP:    util.Uint32ToIP(reg.GetVirtualIp()),
			Payload:  payload,
		}); err != nil {
			t.Fatalf("update client status failed: %v", err)
		}
	}
	build := func(reg *pb.RegistrationResponse) []*protocol.Packet {
		packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
			Proto: protocol.ProtocolService,
			SrcIP: util.Uint32ToIP(reg.GetVirtualIp()),
			DstIP: util.Uint32ToIP(reg.GetVirtualGateway()),
		})
		if err != nil {
			t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
		}
		return packets
	}

	reportStatus(firstReg, secondReg.GetVirtualIp())
	reportStatus(secondReg, 0)
	if packets := build(firstReg); len(packets) != 2 {
		t.Fatalf("expected initial manual recovery to dispatch one pair, got %d packets", len(packets))
	}
	reportStatus(secondReg, firstReg.GetVirtualIp())
	if packets := build(secondReg); len(packets) != 0 {
		t.Fatalf("expected opposite-direction manual recovery to be deduplicated, got %d packets", len(packets))
	}
}

func TestBuildPunchStartPacketsFromStatusSkipsExistingMutualP2P(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: dstReg.GetVirtualIp()},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: srcReg.GetVirtualIp()},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 0 {
		t.Fatalf("expected mutual p2p path to suppress punch, got %d packets", len(startPackets))
	}
}

func TestBuildPunchStartPacketsFromStatusSkipsStatusUpdateWhenOneSidedP2PExists(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: dstReg.GetVirtualIp()},
		},
		PunchTriggerReason: pb.PunchTriggerReason_PunchTriggerStatusUpdate,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 0 {
		t.Fatalf("expected one-sided p2p path to suppress status-update punch churn, got %d packets", len(startPackets))
	}
}

func TestBuildPunchStartPacketsFromStatusSkipsStatusReportOnly(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:             srcReg.GetVirtualIp(),
		NatType:            pb.PunchNatType_Cone,
		PunchTriggerReason: pb.PunchTriggerReason_StatusReportOnly,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 0 {
		t.Fatalf("expected status-only report to suppress punch, got %d packets", len(startPackets))
	}
}

func TestBuildPunchStartPacketsFromStatusSkipsForcedRelayClient(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:               srcReg.GetVirtualIp(),
		NatType:              pb.PunchNatType_Cone,
		PunchTriggerReason:   pb.PunchTriggerReason_PunchTriggerManualRequest,
		PreferredChannelMode: pb.ChannelMode_CHANNEL_MODE_RELAY,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 0 {
		t.Fatalf("expected forced relay client to suppress status-triggered punch, got %d packets", len(startPackets))
	}
}

func TestBuildPunchStartPacketsFromStatusAllowsRouteTimeoutRecoveryWhenOneSidedP2PExists(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: dstReg.GetVirtualIp()},
		},
		PunchTriggerReason: pb.PunchTriggerReason_PunchTriggerRouteTimeout,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 2 {
		t.Fatalf("expected route-timeout recovery to still dispatch punch, got %d packets", len(startPackets))
	}
}

func TestBuildPunchStartPacketsFromStatusIncludesLocalEndpointsForPrivateRemoteAddr(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("192.168.10.11"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("192.168.10.12"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		LocalUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("192.168.10.11")), Port: 1111},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		LocalUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("192.168.10.12")), Port: 2222},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 2 {
		t.Fatalf("expected 2 start packets, got %d", len(startPackets))
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	var foundPublic, foundLocal bool
	for _, ep := range start.GetPeerEndpoints() {
		switch {
		case ep.GetIp() == util.IpToUint32(net.ParseIP("9.9.9.9")) && ep.GetPort() == 30002:
			foundPublic = true
		case ep.GetIp() == util.IpToUint32(net.ParseIP("192.168.10.12")) && ep.GetPort() == 2222:
			foundLocal = true
		}
	}
	if !foundPublic || !foundLocal {
		t.Fatalf("expected public and local endpoints for private remote addr, got %+v", start.GetPeerEndpoints())
	}
}

func TestBuildPunchStartPacketsFromStatusIncludesReportedLocalEndpointsForPublicRemoteAddr(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		LocalUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("192.168.10.11")), Port: 1111},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		LocalUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("192.168.10.12")), Port: 2222},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 2 {
		t.Fatalf("expected 2 start packets, got %d", len(startPackets))
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	var foundPublic, foundLocal bool
	for _, ep := range start.GetPeerEndpoints() {
		switch {
		case ep.GetIp() == util.IpToUint32(net.ParseIP("9.9.9.9")) && ep.GetPort() == 30002:
			foundPublic = true
		case ep.GetIp() == util.IpToUint32(net.ParseIP("192.168.10.12")) && ep.GetPort() == 2222:
			foundLocal = true
		}
	}
	if !foundPublic || !foundLocal {
		t.Fatalf("expected public and reported local endpoints for public remote addr, got %+v", start.GetPeerEndpoints())
	}
}

func TestBuildPunchStartPacketsFromStatusIncludesIPv6Endpoints(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
			{Ipv6: net.ParseIP("2606:4700:4700::1111"), Port: 2222},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	foundIPv6 := false
	for _, ep := range start.GetPeerEndpoints() {
		if string(ep.GetIpv6()) == string(net.ParseIP("2606:4700:4700::1111")) && ep.GetPort() == 2222 {
			foundIPv6 = true
			break
		}
	}
	if !foundIPv6 {
		t.Fatalf("expected ipv6 endpoint in punch start, got %+v", start.GetPeerEndpoints())
	}
}

func TestBuildPunchStartPacketsFromStatusPrefersExplicitEndpointPairs(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("3.3.3.3")), Port: 40001},
			{Ip: util.IpToUint32(net.ParseIP("4.4.4.4")), Port: 40002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	if len(start.GetPeerEndpoints()) != 2 {
		t.Fatalf("expected only explicit endpoint pairs, got %+v", start.GetPeerEndpoints())
	}
	for _, ep := range start.GetPeerEndpoints() {
		if ep.GetIp() == util.IpToUint32(net.ParseIP("3.3.3.3")) && ep.GetPort() == 40002 {
			t.Fatalf("unexpected cartesian endpoint %+v", ep)
		}
		if ep.GetIp() == util.IpToUint32(net.ParseIP("4.4.4.4")) && ep.GetPort() == 40001 {
			t.Fatalf("unexpected cartesian endpoint %+v", ep)
		}
	}
}

func TestReconcilePunchSessionsTimeoutMarksFallback(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	sessionID := uint64(9001)
	attempt := uint32(1)
	key := punchSessionKey(sessionID, attempt)
	ctrl.nc.PunchSessions.Set(key, &PunchSession{
		SessionID:      sessionID,
		Source:         util.IpToUint32(net.ParseIP("10.26.0.2")),
		Target:         util.IpToUint32(net.ParseIP("10.26.0.3")),
		Attempt:        attempt,
		DeadlineUnixMs: time.Now().Add(-time.Second).UnixMilli(),
		State:          PunchSessionWaiting,
		RequestedAt:    time.Now().Unix(),
		Ack:            map[uint32]bool{},
		Results:        map[uint32]*pb.PunchResult{},
		RelayFallback:  false,
	})
	ctrl.ReconcilePunchSessions(time.Now().UnixMilli())
	session, ok := ctrl.nc.FindPunchSession(sessionID, attempt)
	if !ok {
		t.Fatalf("session not found")
	}
	if session.State != PunchSessionTimeout {
		t.Fatalf("expected timeout state, got %s", session.State)
	}
	if !session.RelayFallback {
		t.Fatalf("timeout session should require relay fallback")
	}
	pairKey := punchPairKey(session.Source, session.Target)
	retry, ok := ctrl.nc.PunchPairRetry.Get(pairKey)
	if !ok {
		t.Fatalf("retry state not found after timeout")
	}
	if retry.Attempt != 1 {
		t.Fatalf("unexpected retry attempt: %d", retry.Attempt)
	}
	if retry.NextAllowedUnixMs <= time.Now().UnixMilli() {
		t.Fatalf("expected backoff window in future, got %d", retry.NextAllowedUnixMs)
	}
}

func TestBuildPunchStartPacketsFromStatusHonorsRetryPolicy(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	pairKey := punchPairKey(srcReg.GetVirtualIp(), dstReg.GetVirtualIp())
	ctrl.nc.PunchPairRetry.Set(pairKey, PunchRetryState{
		Attempt:           maxPunchAttemptsPerPair,
		NextAllowedUnixMs: 0,
	})
	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected max retry suppression, got %d packets", len(packets))
	}
	ctrl.nc.PunchPairRetry.Set(pairKey, PunchRetryState{
		Attempt:           1,
		NextAllowedUnixMs: time.Now().Add(2 * time.Second).UnixMilli(),
	})
	packets, err = ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected backoff suppression, got %d packets", len(packets))
	}
}

func TestBuildPunchStartPacketsFromStatusManualRequestBypassesRetryPolicy(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:             srcReg.GetVirtualIp(),
		NatType:            pb.PunchNatType_Cone,
		PunchTriggerReason: pb.PunchTriggerReason_PunchTriggerManualRequest,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	pairKey := punchPairKey(srcReg.GetVirtualIp(), dstReg.GetVirtualIp())
	ctrl.nc.PunchPairCooldown.Set(pairKey, struct{}{})
	ctrl.nc.PunchPairRetry.Set(pairKey, PunchRetryState{
		Attempt:           maxPunchAttemptsPerPair,
		NextAllowedUnixMs: time.Now().Add(2 * time.Second).UnixMilli(),
	})
	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("expected manual trigger to bypass suppression, got %d packets", len(packets))
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(packets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	if start.GetTriggerReason() != pb.PunchTriggerReason_PunchTriggerManualRequest {
		t.Fatalf("unexpected trigger reason: %+v", start)
	}
	if start.GetAttempt() != 1 {
		t.Fatalf("expected manual trigger to restart attempts, got %d", start.GetAttempt())
	}
}

func TestFailedRegistrationClearsStalePunchCandidateState(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReq := newBaseRegisterReq("dev-b", "node-b")
	dstRemote := &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222}
	dstReg := mustRegister(t, ctrl, dstReq, dstRemote)

	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:  dstReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}

	delete(ctrl.um.authedDevices, "ms.net|dev-b")
	if _, _, err := registerWithPendingHandshakeCapabilitiesAndVirtualIP(ctrl, newRegistrationPacket(t, dstReq), dstRemote); err == nil {
		t.Fatalf("expected registration auth failure")
	}

	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected stale unauthenticated peer to be excluded from punch, got %d packets", len(packets))
	}
}

func TestListDevicesIncludesOnlineState(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	userA, err := ctrl.UMCreateUserWithID("user-a", "ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID user-a failed: %v", err)
	}
	userATicket, err := ctrl.UMIssueDeviceTicket(userA.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket user-a failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userA.UserID, "ms.net", "dev-a", userATicket.Ticket, []byte("pk-dev-a")); err != nil {
		t.Fatalf("UMAuthDevice user-a failed: %v", err)
	}
	userB, err := ctrl.UMCreateUserWithID("user-b", "ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID user-b failed: %v", err)
	}
	userBTicket, err := ctrl.UMIssueDeviceTicket(userB.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket user-b failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userB.UserID, "ms.net", "dev-b", userBTicket.Ticket, []byte("pk-dev-b")); err != nil {
		t.Fatalf("UMAuthDevice user-b failed: %v", err)
	}
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	srcStatus := &pb.ClientStatusInfo{
		Source:  srcReg.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}

	devices := ctrl.ListDevices("user-a")
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	device := devices[0]
	if device.UserID != "user-a" || device.DeviceID != "dev-a" {
		t.Fatalf("unexpected listed device: %+v", device)
	}
	if device.VirtualIP != util.Uint32ToIP(srcReg.GetVirtualIp()).String() {
		t.Fatalf("unexpected src virtual ip: %+v", device)
	}
	if !device.ControlOnline {
		t.Fatalf("expected src device control-online: %+v", device)
	}
	if other := ctrl.ListDevices("user-b"); len(other) != 1 || other[0].VirtualIP != util.Uint32ToIP(dstReg.GetVirtualIp()).String() || !other[0].ControlOnline {
		t.Fatalf("unexpected user-b device list: %+v", other)
	}
	if device.AuthExpireAtUnix == 0 || device.AuthExpired {
		t.Fatalf("expected auth expiry info on listed device: %+v", device)
	}
}

func TestPersonalSDLUsersInSameGroupAreIsolated(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain:             "ms.net",
		DefaultGatewayID:          "gw-default",
		GatewayTicketSecret:       testGatewayTicketSecret,
		DNSServiceAddr:            "127.0.0.1:53",
		DebugCollectKeepPerDevice: 20,
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"user": {
						Gateway: net.ParseIP("10.26.0.1"),
						Netmask: "255.255.255.0",
					},
				},
			},
		},
	})
	defer ctrl.Stop()

	authPersonalDevice := func(userID, deviceID string, pubKey []byte) {
		t.Helper()
		user, err := ctrl.UMCreateUserWithID(userID, "user.ms.net", "ms.net")
		if err != nil {
			t.Fatalf("UMCreateUserWithID %s failed: %v", userID, err)
		}
		ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "user.ms.net", time.Minute)
		if err != nil {
			t.Fatalf("UMIssueDeviceTicket %s failed: %v", userID, err)
		}
		if _, err := ctrl.UMAuthDevice(user.UserID, "user.ms.net", deviceID, ticket.Ticket, pubKey); err != nil {
			t.Fatalf("UMAuthDevice %s/%s failed: %v", userID, deviceID, err)
		}
	}

	reqA := newBaseRegisterReq("dev-personal-a", "node-a")
	reqA.Token = "user.ms.net"
	authPersonalDevice("sdl-alpha", reqA.GetDeviceId(), reqA.GetDevicePubKey())
	respA := mustRegister(t, ctrl, reqA, &net.UDPAddr{IP: net.ParseIP("1.1.1.10"), Port: 1010})
	alphaNetworkKey := NewNetworkIdentity("user.ms.net", "sdl-alpha").Key()

	reqB := newBaseRegisterReq("dev-personal-b", "node-b")
	reqB.Token = "user.ms.net"
	authPersonalDevice("sdl-beta", reqB.GetDeviceId(), reqB.GetDevicePubKey())
	respB := mustRegister(t, ctrl, reqB, &net.UDPAddr{IP: net.ParseIP("1.1.1.11"), Port: 1111})
	betaNetworkKey := NewNetworkIdentity("user.ms.net", "sdl-beta").Key()

	if respA.GetVirtualIp() != respB.GetVirtualIp() {
		t.Fatalf("personal users should be able to reuse isolated virtual ip, got %s and %s", util.Uint32ToIP(respA.GetVirtualIp()), util.Uint32ToIP(respB.GetVirtualIp()))
	}
	if len(respA.GetDeviceInfoList()) != 0 {
		t.Fatalf("sdl-alpha should not see sdl-beta at registration: %+v", respA.GetDeviceInfoList())
	}
	if len(respB.GetDeviceInfoList()) != 0 {
		t.Fatalf("sdl-beta should not see sdl-alpha at registration: %+v", respB.GetDeviceInfoList())
	}

	betaStatus := &pb.ClientStatusInfo{
		Source:  respB.GetVirtualIp(),
		NatType: pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: respB.GetVirtualGateway()},
		},
	}
	betaStatusPayload, err := proto.Marshal(betaStatus)
	if err != nil {
		t.Fatalf("marshal beta status failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacketInNetwork(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(respB.GetVirtualIp()),
		Payload:  betaStatusPayload,
	}, betaNetworkKey); err != nil {
		t.Fatalf("HandleClientStatusInfoPacketInNetwork beta failed: %v", err)
	}
	alphaClient, ok := ctrl.nc.FindClientByVirtualIPInNetwork(alphaNetworkKey, respA.GetVirtualIp())
	if !ok {
		t.Fatalf("alpha client not found")
	}
	betaClient, ok := ctrl.nc.FindClientByVirtualIPInNetwork(betaNetworkKey, respB.GetVirtualIp())
	if !ok {
		t.Fatalf("beta client not found")
	}
	if alphaClient.DataPlaneReachable || betaClient.DataPlaneReachable != true {
		t.Fatalf("status update crossed personal network: alpha=%+v beta=%+v", alphaClient, betaClient)
	}

	listPacket, err := ctrl.HandlePullDeviceListPacketInNetwork(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPullDeviceList,
		SrcIP:    util.Uint32ToIP(respB.GetVirtualIp()),
		DstIP:    net.ParseIP("0.0.0.1"),
	}, betaNetworkKey)
	if err != nil {
		t.Fatalf("HandlePullDeviceListPacket failed: %v", err)
	}
	var pulled pb.DeviceList
	if err := proto.Unmarshal(listPacket.Payload, &pulled); err != nil {
		t.Fatalf("unmarshal pulled device list failed: %v", err)
	}
	if len(pulled.GetDeviceInfoList()) != 0 {
		t.Fatalf("sdl-beta should not pull sdl-alpha device list: %+v", pulled.GetDeviceInfoList())
	}

	devices := ctrl.ListDevices("sdl-alpha")
	if len(devices) != 1 {
		t.Fatalf("expected one listed device for sdl-alpha, got %+v", devices)
	}
	if devices[0].Group != "user.ms.net" || devices[0].VirtualIP != util.Uint32ToIP(respA.GetVirtualIp()).String() {
		t.Fatalf("unexpected sdl-alpha device view: %+v", devices[0])
	}

	snapshot, err := ctrl.BuildDNSSnapshot("ms.net", "user")
	if err != nil {
		t.Fatalf("BuildDNSSnapshot failed: %v", err)
	}
	if len(snapshot.Records) != 0 {
		t.Fatalf("personal user records must not be exposed through shared DNS snapshot: %+v", snapshot.Records)
	}
}

func TestListDevicesIncludesOfflineAuthedDevices(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	user, err := ctrl.UMCreateUserWithID("user-offline", "ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID failed: %v", err)
	}
	ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(user.UserID, "ms.net", "dev-offline", ticket.Ticket, []byte("pk-dev-offline")); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}

	devices := ctrl.ListDevices(user.UserID)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	device := devices[0]
	if device.DeviceID != "dev-offline" {
		t.Fatalf("unexpected device: %+v", device)
	}
	if device.ControlOnline || device.DataPlaneReachable {
		t.Fatalf("expected offline device state: %+v", device)
	}
	if device.AuthExpireAtUnix == 0 || device.AuthExpired {
		t.Fatalf("expected valid auth expiry on offline device: %+v", device)
	}
}

func TestHandleRegistrationPacketConflictAndAllowIpChange(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
	}, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 3456})
	if resp1.GetVirtualIp() == 0 {
		t.Fatalf("virtual ip should not be zero")
	}
	if resp1.GetEpoch() != 1 {
		t.Fatalf("unexpected epoch: %d", resp1.GetEpoch())
	}
	if len(resp1.GetDeviceInfoList()) != 0 {
		t.Fatalf("unexpected device list length: %d", len(resp1.GetDeviceInfoList()))
	}
	if resp1.GetPublicIp() != util.IpToUint32(net.ParseIP("1.2.3.4")) {
		t.Fatalf("unexpected public ip: %d", resp1.GetPublicIp())
	}
	if resp1.GetPublicPort() != 3456 {
		t.Fatalf("unexpected public port: %d", resp1.GetPublicPort())
	}

	_, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, &pb.RegistrationRequest{
		Token:         "ms.net",
		DeviceId:      "dev-b",
		Name:          "node-b",
		VirtualIp:     resp1.GetVirtualIp(),
		AllowIpChange: false,
		DevicePubKey:  []byte("pk-dev-b"),
		OnlineKxPub:   testOnlineKxPub("dev-b-v1"),
	}), handshakeRemote(t, ctrl, &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 7788}))
	if err == nil {
		t.Fatalf("expected conflict error")
	}

	resp2 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:         "ms.net",
		DeviceId:      "dev-b",
		Name:          "node-b",
		VirtualIp:     resp1.GetVirtualIp(),
		AllowIpChange: true,
		DevicePubKey:  []byte("pk-dev-b"),
		OnlineKxPub:   testOnlineKxPub("dev-b-v2"),
	}, &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 7788})
	if resp2.GetVirtualIp() == resp1.GetVirtualIp() {
		t.Fatalf("allow_ip_change should allocate a different ip")
	}
	if resp2.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch after second registration: %d", resp2.GetEpoch())
	}
	if len(resp2.GetDeviceInfoList()) != 1 {
		t.Fatalf("unexpected device list length: %d", len(resp2.GetDeviceInfoList()))
	}
}

func TestHandleRegistrationPacketReuseSameDeviceIP(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.10"), Port: 10000})
	resp2 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a-updated",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v2"),
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.11"), Port: 10001})

	if resp1.GetVirtualIp() != resp2.GetVirtualIp() {
		t.Fatalf("same device should reuse virtual ip: %d != %d", resp1.GetVirtualIp(), resp2.GetVirtualIp())
	}
	if resp2.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch after re-register: %d", resp2.GetEpoch())
	}
}

func TestHandleRegistrationPacketInvalidRequestedIP(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	_, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		VirtualIp:    util.IpToUint32(net.ParseIP("10.27.0.1")),
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
	}), handshakeRemote(t, ctrl, &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 9999}))
	if err == nil {
		t.Fatalf("expected invalid requested ip error")
	}
}

func TestHandlePullDeviceListPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPullDeviceList,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(resp2.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(resp2.GetVirtualGateway()),
	}
	rs, err := ctrl.HandlePullDeviceListPacket(req)
	if err != nil {
		t.Fatalf("HandlePullDeviceListPacket failed: %v", err)
	}
	if rs.AppProto != protocol.AppProtoPushDeviceList {
		t.Fatalf("unexpected app proto: %v", rs.AppProto)
	}
	var list pb.DeviceList
	if err := proto.Unmarshal(rs.Payload, &list); err != nil {
		t.Fatalf("unmarshal device list failed: %v", err)
	}
	if list.GetEpoch() != resp2.GetEpoch() {
		t.Fatalf("unexpected epoch: %d", list.GetEpoch())
	}
	if len(list.GetDeviceInfoList()) != 1 || list.GetDeviceInfoList()[0].GetVirtualIp() != resp1.GetVirtualIp() {
		t.Fatalf("unexpected device list response: %+v", list.GetDeviceInfoList())
	}
	if list.GetDeviceInfoList()[0].GetDeviceId() != "dev-a" {
		t.Fatalf("unexpected device id in list: %+v", list.GetDeviceInfoList()[0])
	}
	if string(list.GetDeviceInfoList()[0].GetDevicePubKey()) != "pk-dev-a" {
		t.Fatalf("unexpected device pub key in list: %+v", list.GetDeviceInfoList()[0])
	}
	if string(list.GetDeviceInfoList()[0].GetOnlineKxPub()) != string(testOnlineKxPub("dev-a")) {
		t.Fatalf("unexpected online kx pub in list: %+v", list.GetDeviceInfoList()[0])
	}
}

func TestBuildPushDeviceListPacketsForPeerChange(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	packets, err := ctrl.BuildPushDeviceListPacketsForPeerChange(resp2.GetVirtualIp())
	if err != nil {
		t.Fatalf("BuildPushDeviceListPacketsForPeerChange failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 push packet, got %d", len(packets))
	}
	packet := packets[0]
	if packet.AppProto != protocol.AppProtoPushDeviceList {
		t.Fatalf("unexpected app proto: %v", packet.AppProto)
	}
	if !packet.DstIP.Equal(util.Uint32ToIP(resp1.GetVirtualIp())) {
		t.Fatalf("unexpected dst ip: %v", packet.DstIP)
	}
	if !packet.SrcIP.Equal(net.ParseIP("0.0.0.1")) {
		t.Fatalf("unexpected src ip: %v", packet.SrcIP)
	}

	var list pb.DeviceList
	if err := proto.Unmarshal(packet.Payload, &list); err != nil {
		t.Fatalf("unmarshal device list failed: %v", err)
	}
	if list.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch: %d", list.GetEpoch())
	}
	if len(list.GetDeviceInfoList()) != 1 {
		t.Fatalf("unexpected device list length: %d", len(list.GetDeviceInfoList()))
	}
	item := list.GetDeviceInfoList()[0]
	if item.GetVirtualIp() != resp2.GetVirtualIp() || item.GetDeviceId() != "dev-b" {
		t.Fatalf("unexpected device info item: %+v", item)
	}
}

func TestBuildPushDeviceListPacketsForAuthedDeviceChange(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	respA := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	respB := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	record, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-a")
	if !ok {
		t.Fatalf("authed device not found")
	}
	ctrl.exitNodeMu.Lock()
	ctrl.exitNodeApproved[record.UserID] = map[string]bool{"dev-a": true}
	ctrl.exitNodeMu.Unlock()

	packets, err := ctrl.BuildPushDeviceListPacketsForAuthedDeviceChange(record.UserID, "dev-a")
	if err != nil {
		t.Fatalf("BuildPushDeviceListPacketsForAuthedDeviceChange failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 push packet, got %d", len(packets))
	}
	packet := packets[0]
	if !packet.DstIP.Equal(util.Uint32ToIP(respB.GetVirtualIp())) {
		t.Fatalf("unexpected dst ip: %v", packet.DstIP)
	}

	var list pb.DeviceList
	if err := proto.Unmarshal(packet.Payload, &list); err != nil {
		t.Fatalf("unmarshal device list failed: %v", err)
	}
	if len(list.GetDeviceInfoList()) != 1 {
		t.Fatalf("unexpected device list length: %d", len(list.GetDeviceInfoList()))
	}
	item := list.GetDeviceInfoList()[0]
	if item.GetVirtualIp() != respA.GetVirtualIp() || !item.GetExitNodeApproved() {
		t.Fatalf("unexpected exit-node view: %+v", item)
	}
}

func TestHandleDeviceRenamePacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	req := &pb.DeviceRenameRequest{
		RequestId: 7,
		DeviceId:  "dev-b",
		NewName:   "renamed-node",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal rename request failed: %v", err)
	}
	packet := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoDeviceRenameRequest,
		SrcIP:    util.Uint32ToIP(resp2.GetVirtualIp()),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}
	respPacket, changedIP, err := ctrl.HandleDeviceRenamePacket(packet)
	if err != nil {
		t.Fatalf("HandleDeviceRenamePacket failed: %v", err)
	}
	if changedIP != 0 {
		t.Fatalf("unexpected changed ip: %v", changedIP)
	}
	var ack pb.DeviceRenameResponse
	if err := proto.Unmarshal(respPacket.Payload, &ack); err != nil {
		t.Fatalf("unmarshal rename response failed: %v", err)
	}
	if !ack.GetOk() || ack.GetPendingApproval() || ack.GetRequestId() != 7 || ack.GetAppliedName() != "renamed-node" {
		t.Fatalf("unexpected rename response: %+v", ack)
	}

	client, ok := ctrl.nc.FindClientByVirtualIP(resp2.GetVirtualIp())
	if !ok {
		t.Fatalf("renamed client not found")
	}
	if client.Name != "node-b" {
		t.Fatalf("unexpected client name before restart: %+v", client)
	}
	record, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-b")
	if !ok {
		t.Fatalf("authed device not found after rename")
	}
	if record.DisplayName != "renamed-node" {
		t.Fatalf("unexpected persisted display name after rename request: %+v", record)
	}
}

func TestHandleDeviceRenamePacketRejectsDuplicateName(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	req := &pb.DeviceRenameRequest{
		RequestId: 8,
		DeviceId:  "dev-b",
		NewName:   " NODE-A ",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal rename request failed: %v", err)
	}
	packet := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoDeviceRenameRequest,
		SrcIP:    util.Uint32ToIP(resp2.GetVirtualIp()),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}
	respPacket, _, err := ctrl.HandleDeviceRenamePacket(packet)
	if err != nil {
		t.Fatalf("HandleDeviceRenamePacket failed: %v", err)
	}
	var ack pb.DeviceRenameResponse
	if err := proto.Unmarshal(respPacket.Payload, &ack); err != nil {
		t.Fatalf("unmarshal rename response failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "device name already exists" {
		t.Fatalf("expected duplicate-name rejection, got %+v", ack)
	}
	record, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-b")
	if !ok {
		t.Fatalf("authed device not found after rename")
	}
	if record.DisplayName != "node-b" {
		t.Fatalf("duplicate rename should not persist display name: %+v", record)
	}
}

func TestRegistrationAssignsUniqueDisplayName(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "aliyun-jp"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "aliyun-jp"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	client1, ok := ctrl.nc.FindClientByVirtualIP(resp1.GetVirtualIp())
	if !ok {
		t.Fatalf("client dev-a not found")
	}
	client2, ok := ctrl.nc.FindClientByVirtualIP(resp2.GetVirtualIp())
	if !ok {
		t.Fatalf("client dev-b not found")
	}
	if client1.Name != "aliyun-jp" || client2.Name != "aliyun-jp-1" {
		t.Fatalf("unexpected client names: %q %q", client1.Name, client2.Name)
	}
	record1, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-a")
	if !ok {
		t.Fatalf("authed dev-a missing")
	}
	record2, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-b")
	if !ok {
		t.Fatalf("authed dev-b missing")
	}
	if record1.DisplayName != "aliyun-jp" || record2.DisplayName != "aliyun-jp-1" {
		t.Fatalf("unexpected persisted names: %q %q", record1.DisplayName, record2.DisplayName)
	}
}

func TestDeleteAuthedDeviceRemovesRuntimeClient(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	if _, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp()); !ok {
		t.Fatalf("client not found before delete")
	}
	record, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-a")
	if !ok {
		t.Fatalf("authed device not found before delete")
	}
	deleted, err := ctrl.DeleteAuthedDevice(record.UserID, "ms.net", "dev-a")
	if err != nil {
		t.Fatalf("DeleteAuthedDevice failed: %v", err)
	}
	if len(deleted) != 1 || deleted[0].DeviceID != "dev-a" {
		t.Fatalf("unexpected deleted devices: %+v", deleted)
	}
	if _, ok := ctrl.UMGetAuthedDevice("ms.net", "dev-a"); ok {
		t.Fatalf("authed device still exists after delete")
	}
	if _, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp()); ok {
		t.Fatalf("runtime client still exists after delete")
	}
}

func TestPersonalUsersCanShareDeviceDisplayName(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	userA, err := ctrl.UMCreateUserWithID("sdl-alpha", "user.ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID sdl-alpha failed: %v", err)
	}
	userB, err := ctrl.UMCreateUserWithID("sdl-beta", "user.ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID sdl-beta failed: %v", err)
	}
	ticketA, err := ctrl.UMIssueDeviceTicket(userA.UserID, "user.ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket sdl-alpha failed: %v", err)
	}
	ticketB, err := ctrl.UMIssueDeviceTicket(userB.UserID, "user.ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket sdl-beta failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userA.UserID, "user.ms.net", "dev-a", ticketA.Ticket, []byte("pk-dev-a")); err != nil {
		t.Fatalf("UMAuthDevice sdl-alpha failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userB.UserID, "user.ms.net", "dev-b", ticketB.Ticket, []byte("pk-dev-b")); err != nil {
		t.Fatalf("UMAuthDevice sdl-beta failed: %v", err)
	}
	if err := ctrl.UMSetAuthedDeviceDisplayName("user.ms.net", "dev-a", "macbook"); err != nil {
		t.Fatalf("UMSetAuthedDeviceDisplayName dev-a failed: %v", err)
	}
	if err := ctrl.UMSetAuthedDeviceDisplayName("user.ms.net", "dev-b", "MACBOOK"); err != nil {
		t.Fatalf("personal users should be allowed to share display names: %v", err)
	}
}

func TestRegistrationUsesPersistedDisplayName(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	user, err := ctrl.UMCreateUser("alice")
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	deviceID := "dev-persisted-name"
	req := newBaseRegisterReq(deviceID, "runtime-name")
	if _, err := ctrl.UMAuthDevice(user.UserID, "ms.net", deviceID, tk.Ticket, req.GetDevicePubKey()); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
	if err := ctrl.UMSetAuthedDeviceDisplayName("ms.net", deviceID, "persisted-name"); err != nil {
		t.Fatalf("UMSetAuthedDeviceDisplayName failed: %v", err)
	}

	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.9"), Port: 9999})
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.Name != "persisted-name" {
		t.Fatalf("expected persisted display name, got %+v", client)
	}
}

func TestHandleClientStatusInfoPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	status := &pb.ClientStatusInfo{
		Source:     resp.GetVirtualIp(),
		UpStream:   10,
		DownStream: 20,
		NatType:    pb.PunchNatType_Cone,
		LocalUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("192.168.10.2")), Port: 12345},
		},
		PublicUdpEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 54321},
			{Ipv6: net.ParseIP("2606:4700:4700::1111"), Port: 12345},
		},
		P2PList: []*pb.RouteItem{
			{NextIp: util.IpToUint32(net.ParseIP("10.26.0.3"))},
		},
	}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal client status failed: %v", err)
	}
	_, err = ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(resp.GetVirtualIp()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.ClientStatus == nil || !client.ClientStatus.IsCone || client.ClientStatus.UpStream != 10 || client.ClientStatus.DownStream != 20 {
		t.Fatalf("unexpected client status: %+v", client.ClientStatus)
	}
	if len(client.ClientStatus.LocalUDPEndpoints) != 1 || client.ClientStatus.LocalUDPEndpoints[0].String() != "192.168.10.2:12345" {
		t.Fatalf("unexpected local udp endpoints: %+v", client.ClientStatus.LocalUDPEndpoints)
	}
	if len(client.ClientStatus.PublicUDPEndpoints) != 2 {
		t.Fatalf("unexpected public udp endpoints: %+v", client.ClientStatus.PublicUDPEndpoints)
	}
	if !client.DataPlaneReachable {
		t.Fatalf("data plane should be reachable when p2p list is non-empty")
	}
}

func TestHandleClientStatusInfoPacketNoP2PRoute(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	status := &pb.ClientStatusInfo{
		Source:     resp.GetVirtualIp(),
		UpStream:   10,
		DownStream: 20,
		NatType:    pb.PunchNatType_Symmetric,
	}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal client status failed: %v", err)
	}
	_, err = ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(resp.GetVirtualIp()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.DataPlaneReachable {
		t.Fatalf("data plane should be unreachable when p2p list is empty")
	}
}

func TestLeaveByRemoteAddrMarksControlOffline(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), remoteAddr)
	ctrl.LeaveByRemoteAddr(remoteAddr)
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.ControlOnline {
		t.Fatalf("control should be offline after leave")
	}
}

func TestLeaveByRemoteAddrClearsPendingHandshakeCapabilities(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	remoteAddr := handshakeRemote(t, ctrl, &net.UDPAddr{IP: net.ParseIP("1.1.1.13"), Port: 1114})
	ctrl.LeaveByRemoteAddr(remoteAddr)

	regReq := newBaseRegisterReq("dev-cap-clear-a", "node-cap-clear-a")
	ensureAuthed(t, ctrl, regReq.GetToken(), regReq.GetDeviceId(), regReq.GetDevicePubKey())
	respPacket, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, regReq), remoteAddr)
	if err != nil {
		t.Fatalf("expected registration to proceed after leave cleared pending handshake, got %v", err)
	}
	var regResp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &regResp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	netInfo, ok := ctrl.nc.VirtualNetwork.Get(regReq.GetToken())
	if !ok {
		t.Fatalf("expected network info for %s", regReq.GetToken())
	}
	clientInfo, ok := netInfo.Clients[regResp.GetVirtualIp()]
	if !ok {
		t.Fatalf("expected client info for virtual ip %v", util.Uint32ToIP(regResp.GetVirtualIp()))
	}
	if len(clientInfo.Capabilities) != 0 {
		t.Fatalf("expected cleared pending handshake capabilities to stay empty, got %+v", clientInfo.Capabilities)
	}
}

func TestGenerateIPReusesOfflineIPAfterSessionExpiry(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}
	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), remoteAddr)
	ctrl.LeaveByRemoteAddr(remoteAddr)
	ctrl.nc.IPSessions.Delete(NewIpSessionKey("ms.net", util.Uint32ToIP(resp1.GetVirtualIp())))
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	if resp2.GetVirtualIp() != resp1.GetVirtualIp() {
		t.Fatalf("expected reuse ip %v, got %v", resp1.GetVirtualIp(), resp2.GetVirtualIp())
	}
}

func TestRegistrationRequiresAuthedDeviceWhenTicketIssued(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	deviceID := fmt.Sprintf("dev-preauth-%d", time.Now().UnixNano())
	user, err := ctrl.UMCreateUser("alice")
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	req := newBaseRegisterReq(deviceID, "node-a")
	_, err = registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, req), handshakeRemote(t, ctrl, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}))
	if err == nil {
		t.Fatalf("expected registration rejected before certification")
	}
	if _, err := ctrl.UMAuthDevice(user.UserID, "ms.net", deviceID, tk.Ticket, req.GetDevicePubKey()); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
	_ = mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
}

func TestHandleDeviceAuthPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	user, err := ctrl.UMCreateUser("alice")
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	req := &pb.DeviceAuthRequest{UserId: user.UserID, Group: "ms.net", DeviceId: "dev-x", Ticket: tk.Ticket, DevicePubKey: []byte("pk-dev-x")}
	b, _ := proto.Marshal(req)
	packet := &protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoDeviceAuthRequest, SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("0.0.0.1"), Payload: b}
	resp, err := ctrl.HandleDeviceAuthPacket(packet)
	if err != nil {
		t.Fatalf("HandleDeviceAuthPacket failed: %v", err)
	}
	var challenge pb.DeviceAuthChallenge
	if err := proto.Unmarshal(resp.Payload, &challenge); err != nil {
		t.Fatalf("unmarshal challenge failed: %v", err)
	}
	if challenge.GetChallengeId() == "" || len(challenge.GetNonce()) == 0 {
		t.Fatalf("expected challenge response, got %+v", challenge)
	}
}

func TestHandleDeviceAuthProofExpiredChallengeSetsMachineReadableReason(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	req := &pb.DeviceAuthProof{
		ChallengeId:  "missing-challenge",
		DeviceId:     "dev-x",
		DevicePubKey: []byte("pk-dev-x"),
		Signature:    []byte("bad-signature"),
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal auth proof failed: %v", err)
	}
	packet := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoDeviceAuthProof,
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}
	resp, err := ctrl.HandleDeviceAuthProofPacket(packet)
	if err != nil {
		t.Fatalf("HandleDeviceAuthProofPacket failed: %v", err)
	}
	var ack pb.DeviceAuthAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal auth ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "challenge_expired" {
		t.Fatalf("expected challenge_expired reject, ack=%+v", ack)
	}
	if ack.GetErrorReason() != pb.DeviceAuthErrorReason_DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED {
		t.Fatalf("expected machine-readable challenge-expired reason, ack=%+v", ack)
	}
}

func TestBuildRegistrationErrorPacketSetsMachineReadableReason(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	req := &protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: net.ParseIP("10.0.0.2"),
		DstIP: net.ParseIP("0.0.0.1"),
	}
	resp, err := ctrl.BuildRegistrationErrorPacket(
		req,
		fmt.Errorf("client 203.0.113.10:443 missing required handshake capability %q", capabilityUDPEndpointReportV1),
	)
	if err != nil {
		t.Fatalf("BuildRegistrationErrorPacket failed: %v", err)
	}
	var registration pb.RegistrationResponse
	if err := proto.Unmarshal(resp.Payload, &registration); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	if registration.GetErrorCode() != 1004 {
		t.Fatalf("expected error code 1004, got %+v", registration)
	}
	if registration.GetErrorReason() != pb.RegistrationErrorReason_REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY {
		t.Fatalf("expected machine-readable missing-handshake-capability reason, got %+v", registration)
	}
	if !strings.Contains(registration.GetErrorMessage(), "missing required handshake capability") {
		t.Fatalf("expected original reason to be preserved, got %+v", registration)
	}
}

func TestGatewayReportAndRegistrationGrant(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-default", "gateway.middlescale.net:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() || ack.GetGatewayId() != "gw-default" {
		t.Fatalf("unexpected gateway report ack: %+v", ack)
	}

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-gw-a", "node-gw-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if grant.GetGatewayChannel() == nil || grant.GetGatewayChannel().GetAddr() != "quic://gateway.middlescale.net:51820" {
		t.Fatalf("unexpected gateway channel: %+v", grant.GetGatewayChannel())
	}
	if len(grant.GetGatewayCapabilities()) == 0 || grant.GetGatewayCapabilities()[0] != "udp_blind_relay_v1" {
		t.Fatalf("unexpected grant capabilities: %+v", grant.GetGatewayCapabilities())
	}
	if len(grant.GetTicket()) == 0 || grant.GetTicketExpireUnixMs() <= 0 {
		t.Fatalf("expected short-lived ticket in grant: %+v", grant)
	}
	if grant.GetLeaseSecs() != uint32(gatewayGrantLease/time.Second) {
		t.Fatalf("unexpected lease secs: %d", grant.GetLeaseSecs())
	}
	if grant.GetGraceSecs() != uint32(gatewayGrantGrace/time.Second) {
		t.Fatalf("unexpected grace secs: %d", grant.GetGraceSecs())
	}
	if diff := grant.GetTicketExpireUnixMs() - grant.GetSoftRefreshAfterUnixMs(); diff != int64((gatewayGrantSoftRefreshLead / time.Millisecond)) {
		t.Fatalf("unexpected soft refresh lead: %dms", diff)
	}
	if diff := grant.GetHardExpireUnixMs() - grant.GetTicketExpireUnixMs(); diff != 0 {
		t.Fatalf("expected hard expire to match ticket expire, diff=%dms", diff)
	}
	var ticket pb.SignedGatewayTicket
	if err := proto.Unmarshal(grant.GetTicket(), &ticket); err != nil {
		t.Fatalf("unmarshal signed gateway ticket failed: %v", err)
	}
	if ticket.GetAlg() != "hmac-sha256" {
		t.Fatalf("unexpected ticket alg: %s", ticket.GetAlg())
	}
	if !verifyHMACTicketSignature(testGatewayTicketSecret, &ticket) {
		t.Fatalf("expected HMAC-signed gateway ticket")
	}
}

func TestGatewayReportRejectsInvalidSignature(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-bad-sig", "127.0.0.1:51820")
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-bad-sig", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	report.Signature[0] ^= 0xff
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "invalid_signature" {
		t.Fatalf("expected invalid signature reject, ack=%+v", ack)
	}
}

func TestGatewayReportRequiresApprovalForNonDefaultGateway(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-denied", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "gateway not approved" {
		t.Fatalf("expected gateway report reject without admin approval, ack=%+v", ack)
	}
}

func TestGatewayApproveByIDAfterPendingReport(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-pending", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() {
		t.Fatalf("expected first report to be pending approval")
	}
	if err := ctrl.ApproveGatewayNodeByID("gw-pending"); err != nil {
		t.Fatalf("ApproveGatewayNodeByID failed: %v", err)
	}
	regResp := mustRegister(
		t,
		ctrl,
		newBaseRegisterReq("dev-pending-approve", "node-pending-approve"),
		&net.UDPAddr{IP: net.ParseIP("1.1.1.52"), Port: 5252},
	)
	grants := regResp.GetGatewayAccessGrants()
	if len(grants) != 1 || grants[0].GetGatewayId() != "gw-pending" {
		t.Fatalf("expected pending gateway to become grantable immediately after approval, got %+v", grants)
	}
	keepalive := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-pending", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, keepalive))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket after approve failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected gateway report accepted after approval")
	}
}

func TestGatewayDelistByIDRemovesApprovedGateway(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-delist", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() {
		t.Fatalf("expected first report to wait for approval")
	}
	if err := ctrl.ApproveGatewayNodeByID("gw-delist"); err != nil {
		t.Fatalf("ApproveGatewayNodeByID failed: %v", err)
	}
	keepalive := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-delist", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, keepalive))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket after approve failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected gateway report accepted after approval")
	}

	regResp := mustRegister(
		t,
		ctrl,
		newBaseRegisterReq("dev-delist-a", "node-delist-a"),
		&net.UDPAddr{IP: net.ParseIP("1.1.1.61"), Port: 6161},
	)
	grants := regResp.GetGatewayAccessGrants()
	if len(grants) != 1 || grants[0].GetGatewayId() != "gw-delist" {
		t.Fatalf("expected approved gateway grant before delist, got %+v", grants)
	}

	if err := ctrl.DelistGatewayNodeByID("gw-delist"); err != nil {
		t.Fatalf("DelistGatewayNodeByID failed: %v", err)
	}

	regResp = mustRegister(
		t,
		ctrl,
		newBaseRegisterReq("dev-delist-b", "node-delist-b"),
		&net.UDPAddr{IP: net.ParseIP("1.1.1.62"), Port: 6262},
	)
	if grants := regResp.GetGatewayAccessGrants(); len(grants) != 0 {
		t.Fatalf("expected no gateway grants after delist, got %+v", grants)
	}

	retry := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-delist", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, retry))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket after delist failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack after delist failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "gateway not approved" {
		t.Fatalf("expected gateway report reject after delist, ack=%+v", ack)
	}

	var listed *GatewayAdminView
	for _, gateway := range ctrl.ListGateways() {
		if gateway.GatewayID == "gw-delist" {
			gatewayCopy := gateway
			listed = &gatewayCopy
			break
		}
	}
	if listed == nil {
		t.Fatalf("expected gateway to remain visible in admin list after delist")
	}
	if listed.Approved {
		t.Fatalf("expected gateway to be unapproved after delist: %+v", *listed)
	}
	if !listed.Reported {
		t.Fatalf("expected gateway to remain reported after delist: %+v", *listed)
	}
}

func TestGatewayDelistDefaultGatewayRejected(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	if err := ctrl.DelistGatewayNodeByID("gw-default"); err == nil {
		t.Fatalf("expected default gateway delist to fail")
	}
}

func TestListGatewaysDoesNotSynthesizeDefaultRow(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	if got := ctrl.ListGateways(); len(got) != 0 {
		t.Fatalf("expected no synthetic default gateway row, got %+v", got)
	}
}

func TestGatewayReportAllowsConfiguredDefaultGateway(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-default", "gateway.middlescale.net:433", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected default gateway auto-allowed, ack=%+v", ack)
	}
}

func TestGatewayReportRejectsDefaultGatewayWrongHost(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "default", "badhost:29901", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	_, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err == nil || !strings.Contains(err.Error(), "default gateway host must be gateway.middlescale.net") {
		t.Fatalf("expected default gateway host rejection, got %v", err)
	}
}

func TestGatewayReportNormalizesHTTPSChannelInGrant(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	report := newSignedGatewayReportWithChannels(
		t,
		testGatewayTicketSecret,
		"gw-default",
		[]string{"udp_blind_relay_v1"},
		[]*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS,
			Addr:       "https://gateway.middlescale.net/",
			ServerName: "gateway.middlescale.net",
		}},
		time.Now(),
		randomGatewayNonce(t),
	)
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected https gateway report accepted, ack=%+v", ack)
	}

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-gw-https", "node-gw-https"), &net.UDPAddr{IP: net.ParseIP("1.1.1.40"), Port: 4040})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if grant.GetGatewayChannel() == nil {
		t.Fatalf("expected a normalized https channel")
	}
	if grant.GetGatewayChannel().GetAddr() != "https://gateway.middlescale.net/gateway" {
		t.Fatalf("unexpected normalized gateway addr: %+v", grant.GetGatewayChannel())
	}
}

func TestGatewayReportCarriesUDPIdentityInChannelAndGrant(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	publicKey := bytes.Repeat([]byte{7}, 32)
	report := newSignedGatewayReportWithChannels(
		t,
		testGatewayTicketSecret,
		"gw-default",
		[]string{"udp_blind_relay_v1"},
		[]*pb.GatewayChannel{{
			Kind:         pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP,
			Addr:         "udp://gateway.middlescale.net:29901",
			UdpPublicKey: publicKey,
			UdpKeyId:     "udp-key-1",
		}},
		time.Now(),
		randomGatewayNonce(t),
	)
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected UDP gateway report accepted, ack=%+v", ack)
	}

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-gw-udp", "node-gw-udp"), &net.UDPAddr{IP: net.ParseIP("1.1.1.41"), Port: 4141})
	channel := regResp.GetGatewayAccessGrant().GetGatewayChannel()
	if channel == nil {
		t.Fatal("expected UDP gateway channel in grant")
	}
	if channel.GetUdpKeyId() != "udp-key-1" || !bytes.Equal(channel.GetUdpPublicKey(), publicKey) {
		t.Fatalf("unexpected UDP identity in grant channel: %+v", channel)
	}
}

func TestGatewayReportRejectsUDPChannelWithoutIdentity(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	report := newSignedGatewayReportWithChannels(
		t,
		testGatewayTicketSecret,
		"gw-default",
		[]string{"udp_blind_relay_v1"},
		[]*pb.GatewayChannel{{
			Kind: pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP,
			Addr: "udp://gateway.middlescale.net:29901",
		}},
		time.Now(),
		randomGatewayNonce(t),
	)
	_, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err == nil || !strings.Contains(err.Error(), "requires a 32-byte udp_public_key") {
		t.Fatalf("expected missing UDP identity rejection, got %v", err)
	}
}

func TestGatewayReportRejectsHTTPSChannelWithUnexpectedPath(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	report := newSignedGatewayReportWithChannels(
		t,
		testGatewayTicketSecret,
		"gw-default",
		[]string{"udp_blind_relay_v1"},
		[]*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS,
			Addr:       "https://gateway.middlescale.net/legacy",
			ServerName: "gateway.middlescale.net",
		}},
		time.Now(),
		randomGatewayNonce(t),
	)
	_, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err == nil || !strings.Contains(err.Error(), "gateway_channel must include a valid addr") {
		t.Fatalf("expected invalid https path rejection, got %v", err)
	}
}

func TestGatewayGrantIncludesSingleChannel(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-ca",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-ca", "127.0.0.1:51826", []string{"udp_blind_relay_v1"}, "", nil)

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-ca-a", "node-ca-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.32"), Port: 3232})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if grant.GetGatewayChannel() == nil {
		t.Fatalf("expected one gateway channel")
	}
}

func TestCloneGatewayChannelsNormalizesHttpsGatewayPath(t *testing.T) {
	channels := cloneGatewayChannels([]*pb.GatewayChannel{{
		Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS,
		Addr:       "https://gateway.example.com:443",
		ServerName: "gateway.example.com",
	}})
	if len(channels) != 1 {
		t.Fatalf("expected one normalized channel, got %d", len(channels))
	}
	if got := channels[0].GetAddr(); got != "https://gateway.example.com:443/gateway" {
		t.Fatalf("unexpected normalized addr: %s", got)
	}
}

func TestCloneGatewayChannelsDropsUnsupportedHttpsPath(t *testing.T) {
	channels := cloneGatewayChannels([]*pb.GatewayChannel{{
		Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_HTTPS,
		Addr:       "https://gateway.example.com:443/custom",
		ServerName: "gateway.example.com",
	}})
	if len(channels) != 0 {
		t.Fatalf("expected invalid https path to be dropped, got %+v", channels)
	}
}

func TestGatewayApprovalPersistsAcrossControllerRestart(t *testing.T) {
	stateDir := t.TempDir()
	ctrl := newControllerWithStateDir(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}, stateDir)
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-persist", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() {
		t.Fatalf("expected report to wait for approval")
	}
	if err := ctrl.ApproveGatewayNodeByID("gw-persist"); err != nil {
		t.Fatalf("ApproveGatewayNodeByID failed: %v", err)
	}
	ctrl.Stop()

	reloaded := newControllerWithStateDir(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}, stateDir)
	defer reloaded.Stop()
	if !reloaded.isGatewayAllowed("gw-persist", "127.0.0.1:51821") {
		t.Fatalf("expected approved gateway to persist across restart")
	}
}

func TestExitNodeApprovalRequiresDatabase(t *testing.T) {
	cfg := &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}
	ctrl := newControllerWithConfig(t, cfg)
	defer ctrl.Stop()
	user, err := ctrl.UMCreateUserWithID("sdl-user-a", "default.ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID failed: %v", err)
	}
	ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "default.ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(user.UserID, "default.ms.net", "dev-exit", ticket.Ticket, []byte("pk-dev-exit")); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
	if err := ctrl.ApproveExitNode(user.UserID, "dev-exit"); err == nil || !strings.Contains(err.Error(), "requires DATABASE_URL") {
		t.Fatalf("expected DATABASE_URL error, got %v", err)
	}
	list := ctrl.ListExitNodes(user.UserID)
	if len(list) != 0 {
		t.Fatalf("expected no exit-node records before advertise or approval, got %+v", list)
	}
}

func TestExitNodeStatusMarksAdminViewAndDeviceListUsable(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"default": {Gateway: net.ParseIP("10.26.0.1"), Netmask: "255.255.255.0"},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	user, err := ctrl.UMCreateUserWithID("sdl-exit-user", "default.ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID failed: %v", err)
	}
	for _, deviceID := range []string{"dev-a", "dev-b"} {
		ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "default.ms.net", time.Minute)
		if err != nil {
			t.Fatalf("UMIssueDeviceTicket failed: %v", err)
		}
		if _, err := ctrl.UMAuthDevice(user.UserID, "default.ms.net", deviceID, ticket.Ticket, []byte("pk-"+deviceID)); err != nil {
			t.Fatalf("UMAuthDevice failed: %v", err)
		}
	}

	regA := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "default.ms.net",
		Name:         "node-a",
		DeviceId:     "dev-a",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a"),
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12001})
	regB := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "default.ms.net",
		Name:         "node-b",
		DeviceId:     "dev-b",
		DevicePubKey: []byte("pk-dev-b"),
		OnlineKxPub:  testOnlineKxPub("dev-b"),
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12002})

	ctrl.exitNodeMu.Lock()
	ctrl.exitNodeApproved[user.UserID] = map[string]bool{"dev-b": true}
	ctrl.exitNodeMu.Unlock()
	status := &pb.ClientStatusInfo{
		Source:               regB.GetVirtualIp(),
		PreferredChannelMode: pb.ChannelMode_CHANNEL_MODE_AUTO,
		ExitNodeAdvertised:   true,
		ExitNodeLocalReady:   true,
	}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal ClientStatusInfo failed: %v", err)
	}
	changed, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(regB.GetVirtualIp()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected exit-node status change to request device-list push")
	}

	adminList := ctrl.ListExitNodes(user.UserID)
	if len(adminList) != 1 {
		t.Fatalf("expected user exit-node list to include exit-node records only, got %+v", adminList)
	}
	defaultAdminList := ctrl.ListExitNodes("")
	if len(defaultAdminList) != 1 {
		t.Fatalf("expected default exit-node list to include advertised candidates only, got %+v", defaultAdminList)
	}
	if defaultAdminList[0].DeviceID != "dev-b" || !defaultAdminList[0].Advertised || !defaultAdminList[0].Approved || !defaultAdminList[0].Usable {
		t.Fatalf("expected default list to include usable dev-b candidate, got %+v", defaultAdminList[0])
	}
	var adminB *ExitNodeAdminView
	for i := range adminList {
		if adminList[i].DeviceID == "dev-b" {
			adminB = &adminList[i]
			break
		}
	}
	if adminB == nil || !adminB.Advertised || !adminB.Approved || !adminB.Usable {
		t.Fatalf("expected dev-b to be advertised, approved, and usable, got %+v", adminB)
	}

	packet, err := ctrl.HandlePullDeviceListPacket(&protocol.Packet{
		AppProto: protocol.AppProtoPullDeviceList,
		SrcIP:    util.Uint32ToIP(regA.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(regA.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("HandlePullDeviceListPacket failed: %v", err)
	}
	var list pb.DeviceList
	if err := proto.Unmarshal(packet.Payload, &list); err != nil {
		t.Fatalf("unmarshal device list failed: %v", err)
	}
	if len(list.GetDeviceInfoList()) != 1 {
		t.Fatalf("expected node-a to see node-b only, got %+v", list.GetDeviceInfoList())
	}
	peer := list.GetDeviceInfoList()[0]
	if peer.GetDeviceId() != "dev-b" || !peer.GetExitNodeAdvertised() || !peer.GetExitNodeApproved() || !peer.GetExitNodeUsable() {
		t.Fatalf("expected node-b exit-node flags in device list, got %+v", peer)
	}
}

func TestResolveExitNodeApprovalTarget(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {Groups: map[string]config.GroupConfig{
				"default": {Gateway: net.ParseIP("10.26.0.1"), Netmask: "255.255.255.0"},
			}},
		},
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	user, err := ctrl.UMCreateUserWithID("exit-user", "default.ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID failed: %v", err)
	}
	for _, deviceID := range []string{"dev-jp", "dev-hk"} {
		ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "default.ms.net", time.Minute)
		if err != nil {
			t.Fatalf("UMIssueDeviceTicket failed: %v", err)
		}
		if _, err := ctrl.UMAuthDevice(user.UserID, "default.ms.net", deviceID, ticket.Ticket, []byte("pk-"+deviceID)); err != nil {
			t.Fatalf("UMAuthDevice(%s) failed: %v", deviceID, err)
		}
	}
	if err := ctrl.UMSetAuthedDeviceDisplayName("default.ms.net", "dev-jp", "aliyun-jp"); err != nil {
		t.Fatalf("UMSetAuthedDeviceDisplayName failed: %v", err)
	}

	resolvedUser, resolvedDevice, err := ctrl.resolveExitNodeApprovalTarget("", "dev-hk", "")
	if err != nil || resolvedUser != user.UserID || resolvedDevice != "dev-hk" {
		t.Fatalf("unexpected device-id resolution: user=%q device=%q err=%v", resolvedUser, resolvedDevice, err)
	}
	resolvedUser, resolvedDevice, err = ctrl.resolveExitNodeApprovalTarget(user.UserID, "", "aliyun-jp")
	if err != nil || resolvedUser != user.UserID || resolvedDevice != "dev-jp" {
		t.Fatalf("unexpected name resolution: user=%q device=%q err=%v", resolvedUser, resolvedDevice, err)
	}
	if _, _, err := ctrl.resolveExitNodeApprovalTarget("", "", "aliyun-jp"); err == nil || !strings.Contains(err.Error(), "user_id is required") {
		t.Fatalf("expected name-without-user error, got %v", err)
	}
}

func TestExitNodeListIncludesUnapprovedAdvertisedCandidates(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"default": {Gateway: net.ParseIP("10.26.0.1"), Netmask: "255.255.255.0"},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	user, err := ctrl.UMCreateUserWithID("sdl-exit-candidate-user", "default.ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID failed: %v", err)
	}
	ticket, err := ctrl.UMIssueDeviceTicket(user.UserID, "default.ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(user.UserID, "default.ms.net", "dev-exit", ticket.Ticket, []byte("pk-dev-exit")); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
	reg := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "default.ms.net",
		Name:         "node-exit",
		DeviceId:     "dev-exit",
		DevicePubKey: []byte("pk-dev-exit"),
		OnlineKxPub:  testOnlineKxPub("dev-exit"),
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12003})

	status := &pb.ClientStatusInfo{
		Source:               reg.GetVirtualIp(),
		PreferredChannelMode: pb.ChannelMode_CHANNEL_MODE_AUTO,
		ExitNodeAdvertised:   true,
		ExitNodeLocalReady:   true,
	}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal ClientStatusInfo failed: %v", err)
	}
	if _, err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(reg.GetVirtualIp()),
		Payload:  payload,
	}); err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}

	adminList := ctrl.ListExitNodes("")
	if len(adminList) != 1 {
		t.Fatalf("expected default list to include unapproved exit-node candidate, got %+v", adminList)
	}
	candidate := adminList[0]
	if candidate.UserID != user.UserID || candidate.DeviceID != "dev-exit" || !candidate.Advertised || !candidate.LocalReady {
		t.Fatalf("unexpected candidate view: %+v", candidate)
	}
	if candidate.Approved || candidate.Usable {
		t.Fatalf("unapproved candidate should not be approved or usable: %+v", candidate)
	}
}

func TestGatewaySignedKeepaliveReplayRejected(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-replay", "127.0.0.1:51822")
	first := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-replay", "127.0.0.1:51822", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first))
	if err != nil {
		t.Fatalf("first HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected first report accepted, ack=%+v", ack)
	}
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first))
	if err != nil {
		t.Fatalf("replay HandleGatewayReportPacket failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal replay ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "replayed_nonce" {
		t.Fatalf("expected replay rejection, ack=%+v", ack)
	}
}

func TestGatewaySignedKeepaliveRejectsStaleTimestamp(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-stale", "127.0.0.1:51823")
	first := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-stale", "127.0.0.1:51823", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	if _, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first)); err != nil {
		t.Fatalf("first HandleGatewayReportPacket failed: %v", err)
	}
	stale := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-stale", "127.0.0.1:51823", []string{"udp_blind_relay_v1"}, time.Now().Add(-3*gatewayReportFreshnessWindow), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, stale))
	if err != nil {
		t.Fatalf("stale HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal stale ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "stale_report_timestamp" {
		t.Fatalf("expected stale timestamp rejection, ack=%+v", ack)
	}
}

func TestRegistrationSkipsExpiredGatewayLease(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.gatewayAllow["gw-default"] = "127.0.0.1:51824"
	ctrl.gatewayNodes["gw-default"] = GatewayNodeInfo{
		GatewayID:    "gw-default",
		Endpoint:     "127.0.0.1:51822",
		Capabilities: []string{"udp_blind_relay_v1"},
		UpdatedAt:    time.Now().Add(-2 * gatewayNodeLease),
	}
	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-expired-a", "node-expired-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})
	if regResp.GetGatewayAccessGrant() != nil || len(regResp.GetGatewayAccessGrants()) != 0 {
		t.Fatalf("expected expired gateway lease to produce no gateway grant")
	}
}

func TestRegistrationIncludesAllApprovedAliveGateways(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)
	ctrl.RegisterGatewayNode("jp-1", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-multi-a", "node-multi-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.31"), Port: 3131})
	if regResp.GetGatewayAccessGrant() == nil {
		t.Fatalf("expected legacy single gateway access grant in registration response")
	}
	grants := regResp.GetGatewayAccessGrants()
	if len(grants) != 2 {
		t.Fatalf("expected two gateway access grants, got %d", len(grants))
	}
	ids := make([]string, 0, len(grants))
	for _, grant := range grants {
		ids = append(ids, grant.GetGatewayId())
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "gw-default,jp-1" {
		t.Fatalf("unexpected gateway grant ids: %v", ids)
	}
	if regResp.GetGatewayAccessGrant().GetGatewayId() != "gw-default" {
		t.Fatalf("expected default gateway to remain primary legacy grant, got %s", regResp.GetGatewayAccessGrant().GetGatewayId())
	}
}

func TestStaleGatewayIsRetainedForExistingClientButNotAssignedToNewClient(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)
	ctrl.RegisterGatewayNode("jp-1", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)

	firstReq := newBaseRegisterReq("dev-stale-existing-a", "node-stale-existing-a")
	firstResp := mustRegister(t, ctrl, firstReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.71"), Port: 7171})
	if len(firstResp.GetGatewayAccessGrants()) != 2 {
		t.Fatalf("expected first client to receive two gateway grants")
	}
	var staleSessionID uint64
	for _, grant := range firstResp.GetGatewayAccessGrants() {
		if grant.GetGatewayId() == "jp-1" {
			staleSessionID = grant.GetSessionId()
		}
	}
	if staleSessionID == 0 {
		t.Fatalf("expected jp-1 grant in first registration")
	}

	ctrl.gatewayMu.Lock()
	node := ctrl.gatewayNodes["jp-1"]
	node.UpdatedAt = time.Now().Add(-2 * gatewayNodeLease)
	ctrl.gatewayNodes["jp-1"] = node
	ctrl.gatewayMu.Unlock()

	firstNetworkKey := NewNetworkIdentity(firstReq.GetToken(), "").Key()
	existingGrants, _ := ctrl.buildGatewayAccessGrantsForExistingClient(firstNetworkKey, firstResp.GetVirtualIp(), firstReq.GetDeviceId())
	if len(existingGrants) != 2 {
		t.Fatalf("expected existing client to retain stale gateway grant, got %d grants", len(existingGrants))
	}
	if existingGrants[0].GetGatewayId() != "gw-default" {
		t.Fatalf("expected default gateway to remain primary, got %s", existingGrants[0].GetGatewayId())
	}
	var retainedSessionID uint64
	for _, grant := range existingGrants {
		if grant.GetGatewayId() == "jp-1" {
			retainedSessionID = grant.GetSessionId()
		}
	}
	if retainedSessionID != staleSessionID {
		t.Fatalf("expected stale gateway session %d to be retained, got %d", staleSessionID, retainedSessionID)
	}
	refreshedGrants, _, _ := ctrl.buildGatewayAccessGrantsForRefresh(
		firstNetworkKey,
		firstResp.GetVirtualIp(),
		firstReq.GetDeviceId(),
		staleSessionID,
		false,
	)
	if len(refreshedGrants) != 2 {
		t.Fatalf("expected refresh to retain stale gateway grant, got %d grants", len(refreshedGrants))
	}
	reconnectedResp := mustRegister(
		t,
		ctrl,
		firstReq,
		&net.UDPAddr{IP: net.ParseIP("1.1.1.75"), Port: 7575},
	)
	if len(reconnectedResp.GetGatewayAccessGrants()) != 2 {
		t.Fatalf("expected reconnecting client to retain stale gateway grant")
	}

	secondReq := newBaseRegisterReq("dev-stale-existing-b", "node-stale-existing-b")
	secondResp := mustRegister(t, ctrl, secondReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.72"), Port: 7272})
	grants := secondResp.GetGatewayAccessGrants()
	if len(grants) != 1 || grants[0].GetGatewayId() != "gw-default" {
		t.Fatalf("expected new client to receive only alive gateway, got %+v", grants)
	}
}

func TestGatewayChangePushRetainsStaleGatewayForExistingClient(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)
	ctrl.RegisterGatewayNode("jp-1", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)
	regReq := newBaseRegisterReq("dev-stale-push-a", "node-stale-push-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.73"), Port: 7373})

	ctrl.gatewayMu.Lock()
	node := ctrl.gatewayNodes["jp-1"]
	node.UpdatedAt = time.Now().Add(-2 * gatewayNodeLease)
	ctrl.gatewayNodes["jp-1"] = node
	ctrl.gatewayMu.Unlock()

	packets, err := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded()
	if err != nil {
		t.Fatalf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded failed: %v", err)
	}
	if len(packets) == 0 {
		t.Fatalf("expected gateway policy change push")
	}
	var pushed pb.DeviceList
	found := false
	for _, packet := range packets {
		if !packet.DstIP.Equal(util.Uint32ToIP(regResp.GetVirtualIp())) {
			continue
		}
		if err := proto.Unmarshal(packet.Payload, &pushed); err != nil {
			t.Fatalf("unmarshal gateway change push failed: %v", err)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("expected push for existing client")
	}
	if len(pushed.GetGatewayAccessGrants()) != 2 {
		t.Fatalf("expected push to retain stale gateway grant, got %+v", pushed.GetGatewayAccessGrants())
	}
}

func TestDelistRemovesRetainedStaleGatewayGrant(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)
	ctrl.RegisterGatewayNode("jp-1", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)
	regReq := newBaseRegisterReq("dev-stale-delist-a", "node-stale-delist-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.74"), Port: 7474})

	ctrl.gatewayMu.Lock()
	node := ctrl.gatewayNodes["jp-1"]
	node.UpdatedAt = time.Now().Add(-2 * gatewayNodeLease)
	ctrl.gatewayNodes["jp-1"] = node
	ctrl.gatewayMu.Unlock()

	if err := ctrl.DelistGatewayNodeByID("jp-1"); err != nil {
		t.Fatalf("DelistGatewayNodeByID failed: %v", err)
	}
	grants, _ := ctrl.buildGatewayAccessGrantsForExistingClient(NewNetworkIdentity(regReq.GetToken(), "").Key(), regResp.GetVirtualIp(), regReq.GetDeviceId())
	if len(grants) != 1 || grants[0].GetGatewayId() != "gw-default" {
		t.Fatalf("expected delist to revoke stale gateway grant, got %+v", grants)
	}
	for _, cached := range ctrl.gatewayGrantCache {
		if cached.gatewayID == "jp-1" {
			t.Fatalf("expected delist to remove cached jp-1 grants")
		}
	}
}

func TestPushDeviceListReusesGatewayGrantSession(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-reuse-a", "node-reuse-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.41"), Port: 4141})
	grant1 := resp1.GetGatewayAccessGrant()
	if grant1 == nil {
		t.Fatalf("expected gateway access grant in first registration response")
	}
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-reuse-b", "node-reuse-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.42"), Port: 4242})

	packets, err := ctrl.BuildPushDeviceListPacketsForPeerChange(resp2.GetVirtualIp())
	if err != nil {
		t.Fatalf("BuildPushDeviceListPacketsForPeerChange failed: %v", err)
	}
	var pushed *pb.DeviceList
	for _, packet := range packets {
		if !packet.DstIP.Equal(util.Uint32ToIP(resp1.GetVirtualIp())) {
			continue
		}
		var list pb.DeviceList
		if err := proto.Unmarshal(packet.Payload, &list); err != nil {
			t.Fatalf("unmarshal device list failed: %v", err)
		}
		pushed = &list
		break
	}
	if pushed == nil {
		t.Fatalf("expected push device list for first client")
	}
	if len(pushed.GetGatewayAccessGrants()) != 1 {
		t.Fatalf("expected one pushed gateway grant, got %d", len(pushed.GetGatewayAccessGrants()))
	}
	if pushed.GetGatewayPolicyRev() == 0 {
		t.Fatalf("expected non-zero gateway policy rev in push")
	}
	pushedGrant := pushed.GetGatewayAccessGrants()[0]
	if pushedGrant.GetPolicyRev() != pushed.GetGatewayPolicyRev() {
		t.Fatalf("expected pushed grant policy rev %d to match message rev %d", pushedGrant.GetPolicyRev(), pushed.GetGatewayPolicyRev())
	}
	if pushedGrant.GetSessionId() != grant1.GetSessionId() {
		t.Fatalf("expected pushed gateway session to be reused, got %d want %d", pushedGrant.GetSessionId(), grant1.GetSessionId())
	}
	if pushedGrant.GetTicketExpireUnixMs() != grant1.GetTicketExpireUnixMs() {
		t.Fatalf("expected pushed gateway ticket expiry to be reused, got %d want %d", pushedGrant.GetTicketExpireUnixMs(), grant1.GetTicketExpireUnixMs())
	}
}

func TestGatewayPolicyRevAdvancesOnGatewayChangePush(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-a", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-policy-a", "node-policy-a"), &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.51"),
		Port: 5151,
	})
	if regResp.GetGatewayPolicyRev() == 0 {
		t.Fatalf("expected non-zero registration gateway policy rev")
	}

	ctrl.RegisterGatewayNode("gw-b", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)

	packets, err := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded()
	if err != nil {
		t.Fatalf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded failed: %v", err)
	}
	if len(packets) == 0 {
		t.Fatalf("expected gateway change push packets")
	}
	var pushed *pb.DeviceList
	for _, packet := range packets {
		if !packet.DstIP.Equal(util.Uint32ToIP(regResp.GetVirtualIp())) {
			continue
		}
		var list pb.DeviceList
		if err := proto.Unmarshal(packet.Payload, &list); err != nil {
			t.Fatalf("unmarshal gateway change push failed: %v", err)
		}
		pushed = &list
		break
	}
	if pushed == nil {
		t.Fatalf("expected gateway change push for registered client")
	}
	if pushed.GetGatewayPolicyRev() <= regResp.GetGatewayPolicyRev() {
		t.Fatalf("expected gateway policy rev to advance, got push=%d registration=%d", pushed.GetGatewayPolicyRev(), regResp.GetGatewayPolicyRev())
	}
	for _, grant := range pushed.GetGatewayAccessGrants() {
		if grant.GetPolicyRev() != pushed.GetGatewayPolicyRev() {
			t.Fatalf("expected pushed grant policy rev %d to match message rev %d", grant.GetPolicyRev(), pushed.GetGatewayPolicyRev())
		}
	}
}

func TestRefreshGatewayGrantPacketReusesSessionWhenMatched(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-refresh-a", "node-refresh-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.30"), Port: 3030})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}

	req := &pb.RefreshGatewayGrantRequest{
		VirtualIp:     regResp.GetVirtualIp(),
		DeviceId:      regReq.GetDeviceId(),
		LastSessionId: grant.GetSessionId(),
		LastPolicyRev: grant.GetPolicyRev(),
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal refresh gateway grant request failed: %v", err)
	}
	respPacket, err := ctrl.HandleRefreshGatewayGrantPacket(&protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantRequest,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(regResp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(regResp.GetVirtualGateway()),
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("HandleRefreshGatewayGrantPacket failed: %v", err)
	}

	var resp pb.RefreshGatewayGrantResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal refresh gateway grant response failed: %v", err)
	}
	if resp.GetHasUpdate() {
		t.Fatalf("expected no-change refresh response, got %+v", resp)
	}
	if resp.GetResult() != pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE {
		t.Fatalf("expected no-change refresh result, got %v", resp.GetResult())
	}
	if resp.GetReason() != "gateway grant unchanged" {
		t.Fatalf("unexpected refresh reason: %s", resp.GetReason())
	}
	if resp.GetGatewayAccessGrant() != nil || len(resp.GetGatewayAccessGrants()) != 0 {
		t.Fatalf("expected no grant payload for no-change refresh response, got %+v", resp)
	}
	if resp.GetGatewayPolicyRev() != grant.GetPolicyRev() {
		t.Fatalf("expected gateway policy rev to stay at %d, got %d", grant.GetPolicyRev(), resp.GetGatewayPolicyRev())
	}
}

func TestRefreshGatewayGrantPacketReusesAllGatewaySessionsWhenOneSessionMatches(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)
	ctrl.RegisterGatewayNode("jp-1", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-refresh-multi-a", "node-refresh-multi-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.36"), Port: 3636})
	grants := regResp.GetGatewayAccessGrants()
	if len(grants) != 2 {
		t.Fatalf("expected two gateway grants in registration response, got %d", len(grants))
	}

	var matchedGrant *pb.GatewayAccessGrant
	for _, grant := range grants {
		if grant.GetGatewayId() == "gw-default" {
			matchedGrant = grant
			break
		}
	}
	if matchedGrant == nil {
		t.Fatalf("expected gw-default grant in registration response")
	}

	req := &pb.RefreshGatewayGrantRequest{
		VirtualIp:     regResp.GetVirtualIp(),
		DeviceId:      regReq.GetDeviceId(),
		LastSessionId: matchedGrant.GetSessionId(),
		LastPolicyRev: regResp.GetGatewayPolicyRev(),
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal refresh gateway grant request failed: %v", err)
	}
	respPacket, err := ctrl.HandleRefreshGatewayGrantPacket(&protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantRequest,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(regResp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(regResp.GetVirtualGateway()),
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("HandleRefreshGatewayGrantPacket failed: %v", err)
	}

	var resp pb.RefreshGatewayGrantResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal refresh gateway grant response failed: %v", err)
	}
	if resp.GetHasUpdate() {
		t.Fatalf("expected multi-gateway refresh response to remain unchanged, got %+v", resp)
	}
	if resp.GetResult() != pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE {
		t.Fatalf("expected no-change refresh result, got %v", resp.GetResult())
	}
	if resp.GetReason() != "gateway grant unchanged" {
		t.Fatalf("unexpected refresh reason: %s", resp.GetReason())
	}
	if resp.GetGatewayAccessGrant() != nil || len(resp.GetGatewayAccessGrants()) != 0 {
		t.Fatalf("expected no grant payload for no-change refresh response, got %+v", resp)
	}
	if resp.GetGatewayPolicyRev() != regResp.GetGatewayPolicyRev() {
		t.Fatalf("expected gateway policy rev to stay at %d, got %d", regResp.GetGatewayPolicyRev(), resp.GetGatewayPolicyRev())
	}
}

func TestRefreshGatewayGrantPacketForceReissueRotatesSession(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-refresh-force-a", "node-refresh-force-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.32"), Port: 3232})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}

	req := &pb.RefreshGatewayGrantRequest{
		VirtualIp:     regResp.GetVirtualIp(),
		DeviceId:      regReq.GetDeviceId(),
		LastSessionId: grant.GetSessionId(),
		ForceReissue:  true,
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal refresh gateway grant request failed: %v", err)
	}
	respPacket, err := ctrl.HandleRefreshGatewayGrantPacket(&protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantRequest,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(regResp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(regResp.GetVirtualGateway()),
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("HandleRefreshGatewayGrantPacket failed: %v", err)
	}

	var resp pb.RefreshGatewayGrantResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal refresh gateway grant response failed: %v", err)
	}
	if !resp.GetHasUpdate() {
		t.Fatalf("expected refreshed grant, got %+v", resp)
	}
	if resp.GetResult() != pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_UPDATED {
		t.Fatalf("expected updated refresh result, got %v", resp.GetResult())
	}
	if resp.GetGatewayAccessGrant() == nil {
		t.Fatalf("expected gateway access grant in refresh response")
	}
	if resp.GetGatewayAccessGrant().GetSessionId() == grant.GetSessionId() {
		t.Fatalf("expected force reissue to rotate session id")
	}
}

func TestRefreshGatewayGrantPacketClearsStalePolicy(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-refresh-clear-a", "node-refresh-clear-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.34"), Port: 3434})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}

	ctrl.gatewayMu.Lock()
	delete(ctrl.gatewayNodes, "gw-default")
	ctrl.gatewayMu.Unlock()

	req := &pb.RefreshGatewayGrantRequest{
		VirtualIp:     regResp.GetVirtualIp(),
		DeviceId:      regReq.GetDeviceId(),
		LastSessionId: grant.GetSessionId(),
		LastPolicyRev: grant.GetPolicyRev(),
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal refresh gateway grant request failed: %v", err)
	}
	respPacket, err := ctrl.HandleRefreshGatewayGrantPacket(&protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantRequest,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(regResp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(regResp.GetVirtualGateway()),
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("HandleRefreshGatewayGrantPacket failed: %v", err)
	}

	var resp pb.RefreshGatewayGrantResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal refresh gateway grant response failed: %v", err)
	}
	if !resp.GetHasUpdate() {
		t.Fatalf("expected cleared gateway policy update, got %+v", resp)
	}
	if resp.GetResult() != pb.RefreshGatewayGrantResult_REFRESH_GATEWAY_GRANT_RESULT_REVOKED {
		t.Fatalf("expected revoked refresh result, got %v", resp.GetResult())
	}
	if len(resp.GetGatewayAccessGrants()) != 0 || resp.GetGatewayAccessGrant() != nil {
		t.Fatalf("expected cleared gateway grants, got %+v", resp)
	}
	if resp.GetGatewayPolicyRev() <= grant.GetPolicyRev() {
		t.Fatalf("expected cleared gateway policy rev to advance, got response=%d last=%d", resp.GetGatewayPolicyRev(), grant.GetPolicyRev())
	}
}

func TestGatewayGrantCachePrunesRemovedGateways(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-prune-a", "node-prune-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.33"), Port: 3333})
	if regResp.GetGatewayAccessGrant() == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if len(ctrl.gatewayGrantCache) == 0 {
		t.Fatalf("expected gateway grant cache to be populated")
	}

	ctrl.gatewayMu.Lock()
	delete(ctrl.gatewayNodes, "gw-default")
	ctrl.gatewayMu.Unlock()

	if grants := ctrl.buildGatewayAccessGrants(NewNetworkIdentity(regReq.GetToken(), "").Key(), regResp.GetVirtualIp(), regReq.GetDeviceId()); grants != nil {
		t.Fatalf("expected no grants after removing active gateway, got %+v", grants)
	}
	if len(ctrl.gatewayGrantCache) != 0 {
		t.Fatalf("expected stale gateway grant cache entries to be pruned, got %d", len(ctrl.gatewayGrantCache))
	}
}

func TestBuildDNSSnapshotReturnsRecords(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"default": {Gateway: net.ParseIP("10.26.0.1"), Netmask: "255.255.255.0"},
					"ops":     {Gateway: net.ParseIP("10.26.1.1"), Netmask: "255.255.255.0"},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"quic_stream_relay_v1"}, "", nil)

	req := newBaseRegisterReq("dev-dns-a", "laptop")
	req.Token = "default.ms.net"
	req.Name = "laptop"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.50"), Port: 5050})

	snapshot, err := ctrl.BuildDNSSnapshot("ms.net", "default")
	if err != nil {
		t.Fatalf("BuildDNSSnapshot failed: %v", err)
	}
	if snapshot.Domain != "ms.net" || snapshot.GroupFilter != "default" {
		t.Fatalf("unexpected snapshot scope: %+v", snapshot)
	}
	if snapshot.Epoch == 0 {
		t.Fatalf("expected non-zero epoch")
	}
	if len(snapshot.Networks) != 1 || snapshot.Networks[0].Group != "default" || snapshot.Networks[0].GatewayIP != "10.26.0.1" {
		t.Fatalf("unexpected networks: %+v", snapshot.Networks)
	}
	if len(snapshot.Records) != 1 {
		t.Fatalf("unexpected records: %+v", snapshot.Records)
	}
	record := snapshot.Records[0]
	if record.FQDN != "laptop.default.ms.net" {
		t.Fatalf("unexpected fqdn: %+v", record)
	}
	if record.VirtualIP != util.Uint32ToIP(resp.GetVirtualIp()).String() {
		t.Fatalf("unexpected virtual ip: %+v", record)
	}
	if len(snapshot.Gateways) == 0 || snapshot.Gateways[0].GatewayID != "gw-default" || !snapshot.Gateways[0].Default {
		t.Fatalf("unexpected gateways: %+v", snapshot.Gateways)
	}
}

func TestBuildDNSSnapshotEpochIgnoresReachabilityState(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"default": {Gateway: net.ParseIP("10.26.0.1"), Netmask: "255.255.255.0"},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	req := newBaseRegisterReq("dev-dns-epoch", "epoch-node")
	req.Token = "default.ms.net"
	req.Name = "epoch-node"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.51"), Port: 5151})

	before, err := ctrl.BuildDNSSnapshot("ms.net", "default")
	if err != nil {
		t.Fatalf("BuildDNSSnapshot before failed: %v", err)
	}

	ctrl.nc.VirtualNetwork.mutex.Lock()
	network, ok := ctrl.nc.VirtualNetwork.data["default.ms.net"]
	if !ok || network == nil {
		ctrl.nc.VirtualNetwork.mutex.Unlock()
		t.Fatalf("expected network for default.ms.net")
	}
	client := network.Clients[resp.GetVirtualIp()]
	client.ControlOnline = !client.ControlOnline
	client.DataPlaneReachable = !client.DataPlaneReachable
	client.ControlLastSeen++
	client.DataPlaneLastSeen++
	network.Clients[resp.GetVirtualIp()] = client
	ctrl.nc.VirtualNetwork.mutex.Unlock()

	after, err := ctrl.BuildDNSSnapshot("ms.net", "default")
	if err != nil {
		t.Fatalf("BuildDNSSnapshot after failed: %v", err)
	}
	if before.Epoch != after.Epoch {
		t.Fatalf("expected epoch unchanged for reachability-only update: before=%d after=%d", before.Epoch, after.Epoch)
	}
}

func TestRegistrationUsesConfiguredGroupNetwork(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Groups: map[string]config.GroupConfig{
			"g1.net": {Gateway: net.ParseIP("10.26.1.1"), Netmask: "255.255.255.0"},
			"g2.net": {Gateway: net.ParseIP("10.27.0.1"), Netmask: "255.255.0.0"},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	req := newBaseRegisterReq("dev-g1-a", "node-g1-a")
	req.Token = "g1.net"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.10"), Port: 1112})
	if resp.GetVirtualGateway() != util.IpToUint32(net.ParseIP("10.26.1.1")) {
		t.Fatalf("unexpected g1 gateway: %s", util.Uint32ToIP(resp.GetVirtualGateway()))
	}
	if resp.GetVirtualNetmask() != util.IpToUint32(net.ParseIP("255.255.255.0")) {
		t.Fatalf("unexpected g1 netmask: %s", util.Uint32ToIP(resp.GetVirtualNetmask()))
	}
}

func TestRegistrationResponseIncludesDNSProfile(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain:   "ms.net",
		DNSServers:      []string{"10.26.0.53"},
		DNSMatchDomains: []string{"ms.net"},
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"sales": {
						Gateway:         net.ParseIP("10.26.0.1"),
						Netmask:         "255.255.255.0",
						DNSServers:      []string{"10.26.0.54"},
						DNSMatchDomains: []string{"sales.ms.net", "ms.net"},
					},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	req := newBaseRegisterReq("dev-dns-prof-a", "dns-node")
	req.Token = "sales.ms.net"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.70"), Port: 7070})
	if resp.GetDnsProfile() == nil {
		t.Fatalf("expected dns profile in registration response")
	}
	if got, want := resp.GetDnsProfile().GetServers(), []string{"10.26.0.54"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected dns servers: %v", got)
	}
	if got, want := resp.GetDnsProfile().GetMatchDomains(), []string{"ms.net", "sales.ms.net"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected dns match domains: %v", got)
	}
}

func TestRegistrationResponseAddsGroupQualifiedDNSMatchDomain(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain:   "ms.net",
		DNSServers:      []string{"10.26.0.53"},
		DNSMatchDomains: []string{"ms.net"},
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"default": {
						Gateway: net.ParseIP("10.26.0.1"),
						Netmask: "255.255.255.0",
					},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	req := newBaseRegisterReq("dev-dns-prof-default-a", "www")
	req.Token = "default.ms.net"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.71"), Port: 7071})
	if resp.GetDnsProfile() == nil {
		t.Fatalf("expected dns profile in registration response")
	}
	if got, want := resp.GetDnsProfile().GetMatchDomains(), []string{"default.ms.net", "ms.net"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected dns match domains: %v", got)
	}
}

func TestRegistrationSkipsReservedDNSServiceIPDuringAutoAllocation(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"sales": {
						Gateway:      net.ParseIP("10.26.0.1"),
						Netmask:      "255.255.255.0",
						DNSServiceIP: "10.26.0.53",
					},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	req := newBaseRegisterReq("dev-dns-skip-a", "dns-skip-node")
	req.Token = "sales.ms.net"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.71"), Port: 7171})

	if got := util.Uint32ToIP(resp.GetVirtualIp()).String(); got == "10.26.0.53" {
		t.Fatalf("auto allocation should skip reserved dns service ip, got %s", got)
	}
	if resp.GetDnsProfile() == nil {
		t.Fatalf("expected dns profile in registration response")
	}
	if got, want := resp.GetDnsProfile().GetServers(), []string{"10.26.0.53"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected dns servers: %v", got)
	}
}

func TestRegistrationAcceptsExplicitReservedDNSServiceIP(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		DefaultDomain: "ms.net",
		Domains: map[string]config.DomainConfig{
			"ms.net": {
				Groups: map[string]config.GroupConfig{
					"sales": {
						Gateway:      net.ParseIP("10.26.0.1"),
						Netmask:      "255.255.255.0",
						DNSServiceIP: "10.26.0.53",
					},
				},
			},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	req := newBaseRegisterReq("dev-dns-service", "dns-service")
	req.Token = "sales.ms.net"
	req.VirtualIp = util.IpToUint32(net.ParseIP("10.26.0.53"))
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.72"), Port: 7272})

	if got := util.Uint32ToIP(resp.GetVirtualIp()).String(); got != "10.26.0.53" {
		t.Fatalf("expected reserved dns service ip, got %s", got)
	}
}

func TestHandleDNSQueryPacketProxiesToConfiguredServiceAddr(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	ln, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		n, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		reply := append([]byte("resp:"), buf[:n]...)
		_, _ = ln.WriteToUDP(reply, addr)
	}()

	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DNSServiceAddr:      ln.LocalAddr().String(),
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()

	query := &pb.DnsQueryRequest{
		RequestId: 42,
		Query:     []byte{0x12, 0x34, 0x01, 0x00},
	}
	payload, err := proto.Marshal(query)
	if err != nil {
		t.Fatalf("marshal dns query failed: %v", err)
	}
	respPacket, err := ctrl.HandleDNSQueryPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoDNSQueryRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleDNSQueryPacket failed: %v", err)
	}
	var resp pb.DnsQueryResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal dns query response failed: %v", err)
	}
	if resp.GetRequestId() != 42 {
		t.Fatalf("unexpected request id: %d", resp.GetRequestId())
	}
	if got, want := string(resp.GetResponse()), "resp:\x12\x34\x01\x00"; got != want {
		t.Fatalf("unexpected dns proxy response: %q", got)
	}
	if resp.GetError() != "" {
		t.Fatalf("unexpected dns proxy error: %s", resp.GetError())
	}
	<-done
}

func newTestController(t *testing.T) *Controller {
	t.Helper()
	return newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
}

func newControllerWithConfig(t *testing.T, cfg *config.Config) *Controller {
	t.Helper()
	stateDir := t.TempDir()
	return newControllerWithStateDir(t, cfg, stateDir)
}

func newControllerWithStateDir(t *testing.T, cfg *config.Config, stateDir string) *Controller {
	t.Helper()
	t.Setenv("UM_STORE_JSON_PATH", filepath.Join(stateDir, "um.json"))
	t.Setenv("GATEWAY_STORE_JSON_PATH", filepath.Join(stateDir, "gateways.json"))
	ctrl, err := NewController(cfg, nil)
	if err != nil {
		t.Fatalf("NewController failed: %v", err)
	}
	return ctrl
}

func mustRegister(t *testing.T, ctrl *Controller, req *pb.RegistrationRequest, remoteAddr net.Addr) *pb.RegistrationResponse {
	t.Helper()
	if len(req.GetDevicePubKey()) == 0 {
		req.DevicePubKey = []byte("pk-" + req.GetDeviceId())
	}
	ensureAuthed(t, ctrl, req.GetToken(), req.GetDeviceId(), req.GetDevicePubKey())
	remoteAddr = handshakeRemote(t, ctrl, remoteAddr)
	respPacket, err := registerWithPendingHandshakeCapabilities(ctrl, newRegistrationPacket(t, req), remoteAddr)
	if err != nil {
		t.Fatalf("HandleRegistrationPacket failed: %v", err)
	}
	var resp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	gw, mask, err := ctrl.resolveGroupNetworkConfig(req.GetToken())
	if err != nil {
		t.Fatalf("resolveGroupNetworkConfig failed: %v", err)
	}
	if resp.GetVirtualGateway() != util.IpToUint32(gw) {
		t.Fatalf("unexpected virtual gateway: %d", resp.GetVirtualGateway())
	}
	if resp.GetVirtualNetmask() != util.MaskToUint32(mask) {
		t.Fatalf("unexpected virtual netmask: %d", resp.GetVirtualNetmask())
	}
	virtualIP := resp.GetVirtualIp()
	virtualGateway := resp.GetVirtualGateway()
	virtualNetmask := resp.GetVirtualNetmask()
	if virtualIP&virtualNetmask != virtualGateway&virtualNetmask {
		t.Fatalf("virtual ip %s is not in gateway/netmask network", util.Uint32ToIP(virtualIP))
	}
	broadcast := (virtualGateway & virtualNetmask) | ^virtualNetmask
	if virtualIP == virtualGateway || virtualIP == broadcast {
		t.Fatalf("virtual ip should not be gateway/broadcast: %s", util.Uint32ToIP(virtualIP))
	}
	return &resp
}

func registerWithPendingHandshakeCapabilities(ctrl *Controller, request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	respPacket, _, err := registerWithPendingHandshakeCapabilitiesAndVirtualIP(ctrl, request, remoteAddr)
	return respPacket, err
}

func registerWithPendingHandshakeCapabilitiesAndVirtualIP(ctrl *Controller, request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, uint32, error) {
	respPacket, virtualIP, _, err := ctrl.HandleRegistrationPacketWithVirtualIPAndCapabilities(
		request,
		remoteAddr,
		ctrl.pendingHandshakeCapabilities(remoteAddr),
	)
	return respPacket, virtualIP, err
}

func handshakeRemote(t *testing.T, ctrl *Controller, remoteAddr net.Addr) net.Addr {
	t.Helper()
	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"udp_endpoint_report_v1", "punch_coord_v1", "gateway_ticket_v1"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	if _, err := ctrl.HandleHandshakePacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}, remoteAddr); err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}
	return remoteAddr
}

func randomGatewayNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate gateway nonce failed: %v", err)
	}
	return nonce
}

func newSignedGatewayReport(
	t *testing.T,
	secret string,
	gatewayID string,
	endpoint string,
	capabilities []string,
	reportTime time.Time,
	nonce []byte,
) *pb.GatewayReportRequest {
	t.Helper()
	return newSignedGatewayReportWithChannels(
		t,
		secret,
		gatewayID,
		capabilities,
		[]*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + endpoint,
			ServerName: "127.0.0.1",
		}},
		reportTime,
		nonce,
	)
}

func newSignedGatewayReportWithChannels(
	t *testing.T,
	secret string,
	gatewayID string,
	capabilities []string,
	channels []*pb.GatewayChannel,
	reportTime time.Time,
	nonce []byte,
) *pb.GatewayReportRequest {
	t.Helper()
	report := &pb.GatewayReportRequest{
		GatewayId:    gatewayID,
		Capabilities: append([]string{}, capabilities...),
		ReportUnixMs: reportTime.UnixMilli(),
		Nonce:        append([]byte(nil), nonce...),
		GatewayChannel: func() *pb.GatewayChannel {
			if len(channels) == 0 {
				return nil
			}
			return channels[0]
		}(),
	}
	signGatewayReportForTest(t, secret, report)
	return report
}

func signGatewayReportForTest(t *testing.T, secret string, report *pb.GatewayReportRequest) {
	t.Helper()
	proofBytes, err := marshalGatewayReportProof(report)
	if err != nil {
		t.Fatalf("marshalGatewayReportProof failed: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(proofBytes); err != nil {
		t.Fatalf("build gateway report signature failed: %v", err)
	}
	report.Signature = mac.Sum(nil)
}

func verifyHMACTicketSignature(secret string, ticket *pb.SignedGatewayTicket) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(ticket.GetClaims()); err != nil {
		return false
	}
	return hmac.Equal(mac.Sum(nil), ticket.GetSignature())
}

func newGatewayReportPacket(t *testing.T, report *pb.GatewayReportRequest) *protocol.Packet {
	t.Helper()
	payload, err := proto.Marshal(report)
	if err != nil {
		t.Fatalf("marshal gateway report failed: %v", err)
	}
	return &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoGatewayReportRequest,
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Payload:  payload,
	}
}

func ensureAuthed(t *testing.T, ctrl *Controller, group, deviceID string, devicePubKey []byte) {
	t.Helper()
	if ctrl.UMIsAuthedDevice(group, deviceID) {
		if err := ctrl.UMCheckAuthedDevice(group, deviceID, devicePubKey); err == nil {
			return
		}
	}
	createArgs := []string{fmt.Sprintf("user-%s-%s", group, deviceID)}
	if domainName, _, ok := matchDomainAndGroup(group, ctrl.cfg.Domains); ok {
		createArgs = append(createArgs, domainName)
	} else if strings.Contains(group, ".") {
		createArgs = append(createArgs, group)
	}
	user, err := ctrl.UMCreateUser(createArgs[0], createArgs[1:]...)
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, group, time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	if _, err = ctrl.UMAuthDevice(user.UserID, group, deviceID, tk.Ticket, devicePubKey); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
}

func newRegistrationPacket(t *testing.T, req *pb.RegistrationRequest) *protocol.Packet {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal registration request failed: %v", err)
	}
	return &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoRegistrationRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		Payload:  payload,
	}
}
