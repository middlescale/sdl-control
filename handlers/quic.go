package handlers

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sdl-control/control"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type framedSession interface {
	io.Reader
	io.Writer
	io.Closer
}

type sessionStream struct {
	remoteAddr string
	// rawWriter must stay behind Write/writeFramed so all session output keeps
	// the same framing and per-session serialization guarantees.
	rawWriter io.Writer
	rawCloser io.Closer
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func (s *sessionStream) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFramedWriter(s.rawWriter, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (s *sessionStream) writeFramed(payload []byte) error {
	_, err := s.Write(payload)
	return err
}

type cancelReader interface {
	CancelRead(quic.StreamErrorCode)
}

func (s *sessionStream) close() error {
	if s == nil || s.rawCloser == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if cr, ok := s.rawCloser.(cancelReader); ok {
			cr.CancelRead(0)
		}
		s.closeErr = s.rawCloser.Close()
	})
	return s.closeErr
}

type streamHub struct {
	mu        sync.RWMutex
	byIP      map[uint32]*sessionStream
	byRoute   map[string]*sessionStream
	ipsByAddr map[string]map[string]*sessionStream
}

var errStreamUnavailable = errors.New("stream unavailable")

func logPunchStartDispatch(prefix string, push *protocol.Packet, dispatchErr error) {
	if push == nil || push.DstIP == nil {
		return
	}
	dispatched := dispatchErr == nil
	var start pb.PunchStart
	if err := proto.Unmarshal(push.Payload, &start); err != nil {
		if dispatched {
			log.Debugf("%s: %s", prefix, push.DstIP)
		} else {
			log.Warnf("%s: %s err=%v", prefix, push.DstIP, dispatchErr)
		}
		return
	}
	peer := "-"
	if start.GetTarget() != 0 {
		peer = util.Uint32ToIP(start.GetTarget()).String()
	}
	if dispatched {
		log.Debugf(
			"%s session_id=%d attempt=%d deliver_to=%s peer=%s peer_endpoint_count=%d",
			prefix,
			start.GetSessionId(),
			start.GetAttempt(),
			push.DstIP,
			peer,
			len(start.GetPeerEndpoints()),
		)
		return
	}
	log.Warnf(
		"%s session_id=%d attempt=%d deliver_to=%s peer=%s peer_endpoint_count=%d err=%v",
		prefix,
		start.GetSessionId(),
		start.GetAttempt(),
		push.DstIP,
		peer,
		len(start.GetPeerEndpoints()),
		dispatchErr,
	)
}

func newStreamHub() *streamHub {
	return &streamHub{
		byIP:      make(map[uint32]*sessionStream),
		byRoute:   make(map[string]*sessionStream),
		ipsByAddr: make(map[string]map[string]*sessionStream),
	}
}

func routeKey(networkKey string, virtualIP uint32) string {
	return strings.TrimSpace(networkKey) + "|" + strconv.FormatUint(uint64(virtualIP), 10)
}

func (h *streamHub) registerSession(remoteAddr net.Addr, networkKey string, virtualIP uint32, stream *sessionStream) {
	if remoteAddr == nil || virtualIP == 0 {
		return
	}
	addr := remoteAddr.String()
	key := routeKey(networkKey, virtualIP)
	var replaced *sessionStream
	h.mu.Lock()
	if previous, ok := h.byRoute[key]; ok && previous != stream {
		h.unregisterLocked(key, previous)
		replaced = previous
	}
	h.byRoute[key] = stream
	if strings.TrimSpace(networkKey) == "" {
		h.byIP[virtualIP] = stream
	}
	ips := h.ipsByAddr[addr]
	if ips == nil {
		ips = make(map[string]*sessionStream)
		h.ipsByAddr[addr] = ips
	}
	ips[key] = stream
	h.mu.Unlock()
	if replaced != nil {
		if closeErr := replaced.close(); closeErr != nil && !isExpectedSessionReadClose(closeErr) {
			log.Debugf("close replaced session %s failed: %v", replaced.remoteAddr, closeErr)
		}
	}
}

func (h *streamHub) unregisterSession(target *sessionStream) {
	if target == nil || target.remoteAddr == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ips, ok := h.ipsByAddr[target.remoteAddr]
	if !ok {
		return
	}
	for key, current := range ips {
		if current != target {
			continue
		}
		if mapped, ok := h.byRoute[key]; ok && mapped == target {
			delete(h.byRoute, key)
		}
		virtualIP, routeOK := routeIP(key)
		if routeOK {
			if mapped, ok := h.byIP[virtualIP]; ok && mapped == target {
				delete(h.byIP, virtualIP)
			}
		}
		delete(ips, key)
	}
	if len(ips) == 0 {
		delete(h.ipsByAddr, target.remoteAddr)
	}
}

func (h *streamHub) unregisterStaleIP(virtualIP uint32, target *sessionStream) {
	h.unregisterStaleRoute("", virtualIP, target)
}

func (h *streamHub) unregisterStaleRoute(networkKey string, virtualIP uint32, target *sessionStream) {
	if target == nil || target.remoteAddr == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unregisterLocked(routeKey(networkKey, virtualIP), target)
}

func (h *streamHub) unregisterLocked(key string, target *sessionStream) {
	current, ok := h.byRoute[key]
	if !ok || current != target {
		return
	}
	delete(h.byRoute, key)
	virtualIP, routeOK := routeIP(key)
	if routeOK {
		if mapped, ok := h.byIP[virtualIP]; ok && mapped == target {
			delete(h.byIP, virtualIP)
		}
	}
	if ips, ok := h.ipsByAddr[target.remoteAddr]; ok {
		if mapped, ok := ips[key]; ok && mapped == target {
			delete(ips, key)
		}
		if len(ips) == 0 {
			delete(h.ipsByAddr, target.remoteAddr)
		}
	}
}

func (h *streamHub) writeToIP(virtualIP uint32, payload []byte) error {
	h.mu.RLock()
	target, ok := h.byIP[virtualIP]
	h.mu.RUnlock()
	if !ok {
		return errStreamUnavailable
	}
	err := target.writeFramed(payload)
	if err != nil {
		h.unregisterSession(target)
		if closeErr := target.close(); closeErr != nil && !isExpectedSessionReadClose(closeErr) {
			log.Debugf("close broken session %s failed: %v", target.remoteAddr, closeErr)
		}
		return fmt.Errorf("write stream %s: %w", target.remoteAddr, err)
	}
	return nil
}

func (h *streamHub) writeToRoute(networkKey string, virtualIP uint32, payload []byte) error {
	if strings.TrimSpace(networkKey) == "" {
		return h.writeToIP(virtualIP, payload)
	}
	h.mu.RLock()
	target, ok := h.byRoute[routeKey(networkKey, virtualIP)]
	h.mu.RUnlock()
	if !ok {
		return errStreamUnavailable
	}
	err := target.writeFramed(payload)
	if err != nil {
		h.unregisterSession(target)
		if closeErr := target.close(); closeErr != nil && !isExpectedSessionReadClose(closeErr) {
			log.Debugf("close broken session %s failed: %v", target.remoteAddr, closeErr)
		}
		return fmt.Errorf("write stream %s: %w", target.remoteAddr, err)
	}
	return nil
}

func routeIP(key string) (uint32, bool) {
	_, ipText, ok := strings.Cut(key, "|")
	if !ok {
		return 0, false
	}
	ip, err := strconv.ParseUint(ipText, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(ip), true
}

var quicStreams = newStreamHub()

func StartQuicServer(ctx context.Context, ctrl *control.Controller, addr string, tlsConfig *tls.Config) {
	serverTLSConfig := tlsConfig.Clone()
	serverTLSConfig.NextProtos = []string{"sdl-control"}
	listener, err := quic.ListenAddr(addr, serverTLSConfig, nil)
	if err != nil {
		log.Fatalf("QUIC listen error: %v", err)
	}
	log.Printf("QUIC control server listening on %s", addr)
	for {
		select {
		case <-ctx.Done():
			log.Println("QUIC server shutting down...")
			listener.Close()
			return
		default:
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleSession(ctrl, conn)
		}
	}
}

func handleSession(ctrl *control.Controller, conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream error: %v", err)
		return
	}
	defer conn.CloseWithError(0, "")
	serveControlSession(ctrl, conn.RemoteAddr(), stream)
}

func serveControlSession(ctrl *control.Controller, remoteAddr net.Addr, session framedSession) {
	log.Debugf("serveControlSession started for remoteAddr=%s", remoteAddr.String())
	var loopErr error
	defer func() {
		if loopErr != nil {
			log.Warnf("serveControlSession ended for remoteAddr=%s, error=%v", remoteAddr.String(), loopErr)
		} else {
			log.Debugf("serveControlSession ended for remoteAddr=%s", remoteAddr.String())
		}
	}()

	ctrl.TouchCipherSession(remoteAddr)
	var sessionCapabilities []string
	var sessionNetworkKey string
	sessionWriter := &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  session,
		rawCloser:  session,
	}
	defer quicStreams.unregisterSession(sessionWriter)
	defer ctrl.LeaveByRemoteAddr(remoteAddr)
	defer sessionWriter.close()
	buf := make([]byte, 4096)
	frameBuf := make([]byte, 0, 8192)
	lastSweepMs := int64(0)
	for {
		n, err := session.Read(buf)
		if err != nil && !(err == io.EOF && n > 0) {
			if isExpectedSessionReadClose(err) {
				break
			}
			log.Warnf("Read error: %v", err)
			loopErr = err
			break
		}
		if n > 0 {
			frameBuf = append(frameBuf, buf[:n]...)
		}
		for {
			if len(frameBuf) < 4 {
				break
			}
			frameLen := int(binary.BigEndian.Uint32(frameBuf[:4]))
			if frameLen <= 0 || frameLen > 1<<20 {
				log.Printf("Invalid frame length: %d", frameLen)
				return
			}
			if len(frameBuf) < 4+frameLen {
				break
			}
			packetRaw := append([]byte(nil), frameBuf[4:4+frameLen]...)
			frameBuf = frameBuf[4+frameLen:]
			packet, err := protocol.Unmarshal(packetRaw)
			if err != nil {
				log.Printf("Unmarshal packet error: %v", err)
				continue
			}
			packet.RouteNetworkKey = sessionNetworkKey
			nowMs := time.Now().UnixMilli()
			if nowMs-lastSweepMs >= 1000 {
				ctrl.ReconcilePunchSessions(nowMs)
				lastSweepMs = nowMs
			}

			if packet.Proto == protocol.ProtocolService {
				var respPacket *protocol.Packet
				var err error
				var virtualIP uint32
				var networkIdentity control.NetworkIdentity
				var deferredPushPackets []*protocol.Packet
				if gatewayPushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
					log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
				} else if len(gatewayPushPackets) > 0 {
					deferredPushPackets = append(deferredPushPackets, gatewayPushPackets...)
				}

				switch packet.AppProto {
				case protocol.AppProtoHandshakeRequest:
					respPacket, err = ctrl.HandleHandshakePacket(packet, remoteAddr)
					if err != nil {
						log.Errorf("HandleHandshakePacket error: %v", err)
						continue
					}
					var handshakeResp pb.HandshakeResponse
					if err := proto.Unmarshal(respPacket.Payload, &handshakeResp); err != nil {
						log.Errorf("HandshakeResponse unmarshal error after handle: %v", err)
						sessionCapabilities = nil
					} else {
						sessionCapabilities = append(sessionCapabilities[:0], handshakeResp.GetCapabilities()...)
					}
				case protocol.AppProtoRegistrationRequest:
					respPacket, virtualIP, networkIdentity, err = ctrl.HandleRegistrationPacketWithVirtualIPAndCapabilities(packet, remoteAddr, sessionCapabilities)
					if err != nil {
						log.Errorf("HandleRegistrationPacket error: %v", err)
						errPacket, packetErr := ctrl.BuildRegistrationErrorPacket(packet, err)
						if packetErr != nil {
							log.Errorf("BuildRegistrationErrorPacket error: %v", packetErr)
							continue
						}
						if writeErr := sessionWriter.writeFramed(errPacket.Marshal()); writeErr != nil {
							log.Errorf("send registration error packet failed: %v", writeErr)
							loopErr = writeErr
							return
						}
						continue
					}
					sessionNetworkKey = networkIdentity.Key()
					quicStreams.registerSession(remoteAddr, sessionNetworkKey, virtualIP, sessionWriter)
					deferredPushPackets, err = ctrl.BuildPushDeviceListPacketsForPeerChangeInNetwork(sessionNetworkKey, virtualIP)
					if err != nil {
						log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", err)
						deferredPushPackets = nil
					}
				case protocol.AppProtoPullDeviceList:
					respPacket, err = ctrl.HandlePullDeviceListPacketInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("HandlePullDeviceListPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDeviceAuthRequest:
					respPacket, err = ctrl.HandleDeviceAuthPacket(packet)
					if err != nil {
						log.Errorf("HandleDeviceAuthPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDeviceAuthProof:
					respPacket, err = ctrl.HandleDeviceAuthProofPacket(packet)
					if err != nil {
						log.Errorf("HandleDeviceAuthProofPacket error: %v", err)
						continue
					}
				case protocol.AppProtoGatewayReportRequest:
					respPacket, err = ctrl.HandleGatewayReportPacket(packet)
					if err != nil {
						log.Errorf("HandleGatewayReportPacket error: %v", err)
						continue
					}
					if gatewayPushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
						log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
					} else if len(gatewayPushPackets) > 0 {
						deferredPushPackets = append(deferredPushPackets, gatewayPushPackets...)
					}
				case protocol.AppProtoRefreshGatewayGrantRequest:
					respPacket, err = ctrl.HandleRefreshGatewayGrantPacketInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("HandleRefreshGatewayGrantPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDNSQueryRequest:
					respPacket, err = ctrl.HandleDNSQueryPacket(packet)
					if err != nil {
						log.Errorf("HandleDNSQueryPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDeviceRenameRequest:
					respPacket, virtualIP, err = ctrl.HandleDeviceRenamePacket(packet)
					if err != nil {
						log.Errorf("HandleDeviceRenamePacket error: %v", err)
						continue
					}
					if virtualIP != 0 {
						deferredPushPackets, err = ctrl.BuildPushDeviceListPacketsForPeerChangeInNetwork(sessionNetworkKey, virtualIP)
						if err != nil {
							log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", err)
							deferredPushPackets = nil
						}
					}
				case protocol.AppProtoClientStatusInfo:
					changed, err := ctrl.HandleClientStatusInfoPacketInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("HandleClientStatusInfoPacket error: %v", err)
					}
					if changed {
						virtualIP = ipToUint32(packet.SrcIP)
						if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForPeerChangeInNetwork(sessionNetworkKey, virtualIP); pushErr != nil {
							log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", pushErr)
						} else {
							for _, push := range pushPackets {
								if push == nil || push.DstIP == nil {
									continue
								}
								if err := quicStreams.writeToRoute(push.RouteNetworkKey, ipToUint32(push.DstIP), push.Marshal()); err != nil {
									log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
								}
							}
						}
					}
					startPackets, err := ctrl.BuildPunchStartPacketsFromStatusInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("BuildPunchStartPacketsFromStatus error: %v", err)
					} else {
						if len(startPackets) > 0 {
							log.Debugf("status-triggered PunchStart packets: %d", len(startPackets))
						}
						for _, push := range startPackets {
							if push == nil || push.DstIP == nil {
								continue
							}
							if err := quicStreams.writeToRoute(push.RouteNetworkKey, ipToUint32(push.DstIP), push.Marshal()); err != nil {
								logPunchStartDispatch("status-triggered PunchStart dispatch failed", push, err)
							} else {
								logPunchStartDispatch("status-triggered PunchStart dispatched", push, nil)
							}
						}
					}
					continue
				case protocol.AppProtoDebugCollectResponse:
					err = ctrl.HandleDebugCollectResponse(packet)
					if err != nil {
						log.Errorf("HandleDebugCollectResponse error: %v", err)
					}
					continue
				case protocol.AppProtoDebugWatchStartResponse:
					err = ctrl.HandleDebugWatchStartResponse(packet)
					if err != nil {
						log.Errorf("HandleDebugWatchStartResponse error: %v", err)
					}
					continue
				case protocol.AppProtoDebugWatchStopResponse:
					err = ctrl.HandleDebugWatchStopResponse(packet)
					if err != nil {
						log.Errorf("HandleDebugWatchStopResponse error: %v", err)
					}
					continue
				case protocol.AppProtoDebugWatchEvent:
					err = ctrl.HandleDebugWatchEvent(packet)
					if err != nil {
						log.Errorf("HandleDebugWatchEvent error: %v", err)
					}
					continue
				case protocol.AppProtoPunchRequest:
					respPacket, err = ctrl.HandlePunchRequestPacketInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("HandlePunchRequestPacket error: %v", err)
						continue
					}
					startPackets, err := ctrl.BuildPunchStartPacketsInNetwork(packet, sessionNetworkKey)
					if err != nil {
						log.Errorf("BuildPunchStartPackets error: %v", err)
						continue
					}
					for _, push := range startPackets {
						if push == nil || push.DstIP == nil {
							continue
						}
						if err := quicStreams.writeToRoute(push.RouteNetworkKey, ipToUint32(push.DstIP), push.Marshal()); err != nil {
							logPunchStartDispatch("PunchStart dispatch failed", push, err)
						} else {
							logPunchStartDispatch("PunchStart dispatched", push, nil)
						}
					}
				case protocol.AppProtoPunchAck:
					err = ctrl.HandlePunchAckPacket(packet)
					if err != nil {
						log.Errorf("HandlePunchAckPacket error: %v", err)
					}
					continue
				case protocol.AppProtoPunchResult:
					err = ctrl.HandlePunchResultPacket(packet)
					if err != nil {
						log.Errorf("HandlePunchResultPacket error: %v", err)
					}
					continue
				default:
					log.Debugf("忽略非 service处理类型 Packet: %d", packet.AppProto)
					continue
				}
				if respPacket == nil {
					continue
				}
				if err := sessionWriter.writeFramed(respPacket.Marshal()); err != nil {
					log.Errorf("Write ServiceResponse error: %v", err)
					loopErr = err
					return
				}
				for _, push := range deferredPushPackets {
					if push == nil || push.DstIP == nil {
						continue
					}
					if err := quicStreams.writeToRoute(push.RouteNetworkKey, ipToUint32(push.DstIP), push.Marshal()); err != nil {
						log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
					}
				}
			} else if packet.Proto == protocol.ProtocolControl {
				respPacket, err := ctrl.HandleControlPacketInNetwork(packet, remoteAddr, sessionNetworkKey)
				if err != nil {
					log.Errorf("HandleControlPacket error: %v", err)
					continue
				}
				if respPacket == nil {
					continue
				}
				if err := sessionWriter.writeFramed(respPacket.Marshal()); err != nil {
					log.Warnf("failed to write control response to %s: %v", remoteAddr.String(), err)
					loopErr = err
					return
				}
			} else {
				log.Infof("忽略非 Service/Control Packet: %s", packet.DebugString())
			}
		}
		if err == io.EOF {
			break
		}

	}
}

func isExpectedSessionReadClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "NO_ERROR") ||
		strings.Contains(msg, "Application error 0x0") ||
		strings.Contains(msg, "closed network connection")
}

func writeFramedStream(stream *quic.Stream, payload []byte) error {
	return writeFramedWriter(stream, payload)
}

func writeFramedWriter(writer io.Writer, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
