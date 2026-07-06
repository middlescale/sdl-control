package control

import (
	"encoding/json"
	"fmt"
	"net"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type DebugWatchStartResult struct {
	RequestID       uint64
	WatchID         uint64
	UserID          string
	Group           string
	Name            string
	DeviceID        string
	VirtualIP       string
	StartedAtUnixMs int64
	ExpireAtUnixMs  int64
	SavedPath       string
}

type DebugWatchStopResult struct {
	RequestID       uint64
	WatchID         uint64
	UserID          string
	Group           string
	Name            string
	DeviceID        string
	VirtualIP       string
	StoppedAtUnixMs int64
	SavedPath       string
}

func (c *Controller) PrepareDebugWatchStartByName(
	name, userID, group string,
	sections []string,
	duration time.Duration,
) (*protocol.Packet, uint32, uint64, error) {
	match, ip, networkKey, err := c.findOnlineDeviceByName(name, userID, group)
	if err != nil {
		return nil, 0, 0, err
	}
	requestID, waiter := c.newDebugWatchStartWaiter()
	durationSec := uint32(duration / time.Second)
	if durationSec == 0 {
		durationSec = 300
	}
	req := &pb.DebugWatchStartRequest{
		RequestId:   requestID,
		Sections:    normalizeDebugSections(sections),
		DurationSec: durationSec,
		Reason:      "admin start_debug_watch",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		c.finishDebugWatchStartWaiter(requestID, waiter)
		return nil, 0, 0, err
	}
	packet := &protocol.Packet{
		Ver:             protocol.V3,
		Proto:           protocol.ProtocolService,
		AppProto:        protocol.AppProtoDebugWatchStartRequest,
		SourceTTL:       protocol.MAX_TTL,
		TTL:             protocol.MAX_TTL,
		SrcIP:           net.ParseIP("0.0.0.1"),
		DstIP:           util.Uint32ToIP(ip),
		Payload:         payload,
		RouteNetworkKey: networkKey,
	}
	_ = match
	return packet, ip, requestID, nil
}

func (c *Controller) AwaitDebugWatchStart(requestID uint64, timeout time.Duration) (DebugWatchStartResult, error) {
	c.debugMu.Lock()
	waiter, ok := c.pendingDebugWatchStart[requestID]
	c.debugMu.Unlock()
	if !ok {
		return DebugWatchStartResult{}, fmt.Errorf("debug watch start request %d not found", requestID)
	}
	select {
	case result := <-waiter:
		if result.WatchID == 0 {
			return DebugWatchStartResult{}, fmt.Errorf("debug watch returned empty watch id")
		}
		return result, nil
	case <-time.After(timeout):
		c.cancelDebugWatchStart(requestID)
		return DebugWatchStartResult{}, fmt.Errorf("debug watch start timed out")
	}
}

func (c *Controller) PrepareDebugWatchStopByName(name, userID, group string) (*protocol.Packet, uint32, uint64, error) {
	match, ip, networkKey, err := c.findOnlineDeviceByName(name, userID, group)
	if err != nil {
		return nil, 0, 0, err
	}
	requestID, waiter := c.newDebugWatchStopWaiter()
	watchID := c.activeDebugWatchIDForDevice(match.DeviceID)
	req := &pb.DebugWatchStopRequest{
		RequestId: requestID,
		WatchId:   watchID,
		Reason:    "admin stop_debug_watch",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		c.finishDebugWatchStopWaiter(requestID, waiter)
		return nil, 0, 0, err
	}
	packet := &protocol.Packet{
		Ver:             protocol.V3,
		Proto:           protocol.ProtocolService,
		AppProto:        protocol.AppProtoDebugWatchStopRequest,
		SourceTTL:       protocol.MAX_TTL,
		TTL:             protocol.MAX_TTL,
		SrcIP:           net.ParseIP("0.0.0.1"),
		DstIP:           util.Uint32ToIP(ip),
		Payload:         payload,
		RouteNetworkKey: networkKey,
	}
	return packet, ip, requestID, nil
}

func (c *Controller) AwaitDebugWatchStop(requestID uint64, timeout time.Duration) (DebugWatchStopResult, error) {
	c.debugMu.Lock()
	waiter, ok := c.pendingDebugWatchStop[requestID]
	c.debugMu.Unlock()
	if !ok {
		return DebugWatchStopResult{}, fmt.Errorf("debug watch stop request %d not found", requestID)
	}
	select {
	case result := <-waiter:
		return result, nil
	case <-time.After(timeout):
		c.cancelDebugWatchStop(requestID)
		return DebugWatchStopResult{}, fmt.Errorf("debug watch stop timed out")
	}
}

func (c *Controller) HandleDebugWatchStartResponse(packet *protocol.Packet) error {
	var resp pb.DebugWatchStartResponse
	if err := proto.Unmarshal(packet.Payload, &resp); err != nil {
		return err
	}
	result := c.decorateDebugWatchStartResult(packet, &resp)
	if resp.GetOk() {
		session := DebugWatchSession{
			WatchID:         result.WatchID,
			UserID:          result.UserID,
			Group:           result.Group,
			Name:            result.Name,
			DeviceID:        result.DeviceID,
			VirtualIP:       result.VirtualIP,
			StartedAtUnixMs: result.StartedAtUnixMs,
			ExpireAtUnixMs:  result.ExpireAtUnixMs,
		}
		if c.debugStore != nil {
			stored, err := c.debugStore.StartWatch(session)
			if err != nil {
				log.Warnf("persist debug watch start failed watch_id=%d err=%v", session.WatchID, err)
			} else {
				session = stored
				result.SavedPath = stored.SessionDir
			}
		}
		c.debugMu.Lock()
		if previousWatchID, ok := c.activeDebugWatchByDevice[session.DeviceID]; ok {
			delete(c.activeDebugWatches, previousWatchID)
		}
		c.activeDebugWatches[session.WatchID] = session
		if session.DeviceID != "" {
			c.activeDebugWatchByDevice[session.DeviceID] = session.WatchID
		}
		waiter, ok := c.pendingDebugWatchStart[result.RequestID]
		if ok {
			delete(c.pendingDebugWatchStart, result.RequestID)
		}
		c.debugMu.Unlock()
		if ok {
			waiter <- result
		}
		return nil
	}
	c.resolveDebugWatchStartFailure(result)
	return nil
}

func (c *Controller) HandleDebugWatchStopResponse(packet *protocol.Packet) error {
	var resp pb.DebugWatchStopResponse
	if err := proto.Unmarshal(packet.Payload, &resp); err != nil {
		return err
	}
	result := c.decorateDebugWatchStopResult(packet, &resp)
	var session DebugWatchSession
	var okSession bool
	c.debugMu.Lock()
	session, okSession = c.activeDebugWatches[result.WatchID]
	if okSession {
		delete(c.activeDebugWatches, result.WatchID)
		if session.DeviceID != "" {
			delete(c.activeDebugWatchByDevice, session.DeviceID)
		}
	}
	waiter, ok := c.pendingDebugWatchStop[result.RequestID]
	if ok {
		delete(c.pendingDebugWatchStop, result.RequestID)
	}
	c.debugMu.Unlock()
	if okSession && c.debugStore != nil {
		if err := c.debugStore.FinishWatch(session, result.StoppedAtUnixMs); err != nil {
			log.Warnf("persist debug watch stop failed watch_id=%d err=%v", result.WatchID, err)
		}
		result.SavedPath = session.SessionDir
	}
	if ok {
		waiter <- result
	}
	return nil
}

func (c *Controller) HandleDebugWatchEvent(packet *protocol.Packet) error {
	var event pb.DebugWatchEvent
	if err := proto.Unmarshal(packet.Payload, &event); err != nil {
		return err
	}
	c.debugMu.Lock()
	session, ok := c.activeDebugWatches[event.GetWatchId()]
	c.debugMu.Unlock()
	if !ok {
		log.Debugf("drop debug watch event for unknown watch_id=%d", event.GetWatchId())
		return nil
	}
	payload := json.RawMessage(event.GetPayloadJson())
	line := map[string]any{
		"watch_id":      event.GetWatchId(),
		"event_unix_ms": event.GetEventUnixMs(),
		"section":       event.GetSection(),
		"event_type":    event.GetEventType(),
	}
	if json.Valid(payload) {
		line["payload"] = payload
	} else {
		line["payload_raw"] = event.GetPayloadJson()
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if c.debugStore != nil {
		return c.debugStore.AppendWatchEvent(session, encoded)
	}
	return nil
}

func (c *Controller) decorateDebugWatchStartResult(packet *protocol.Packet, resp *pb.DebugWatchStartResponse) DebugWatchStartResult {
	result := DebugWatchStartResult{
		RequestID:       resp.GetRequestId(),
		WatchID:         resp.GetWatchId(),
		StartedAtUnixMs: resp.GetStartedAtUnixMs(),
		ExpireAtUnixMs:  resp.GetExpireAtUnixMs(),
		VirtualIP:       packet.SrcIP.String(),
	}
	return c.decorateDebugWatchIdentity(result, packet)
}

func (c *Controller) decorateDebugWatchStopResult(packet *protocol.Packet, resp *pb.DebugWatchStopResponse) DebugWatchStopResult {
	result := DebugWatchStopResult{
		RequestID:       resp.GetRequestId(),
		WatchID:         resp.GetWatchId(),
		StoppedAtUnixMs: resp.GetStoppedAtUnixMs(),
		VirtualIP:       packet.SrcIP.String(),
	}
	identity := c.decorateDebugWatchIdentity(DebugWatchStartResult{VirtualIP: result.VirtualIP}, packet)
	result.UserID = identity.UserID
	result.Group = identity.Group
	result.Name = identity.Name
	result.DeviceID = identity.DeviceID
	result.VirtualIP = identity.VirtualIP
	return result
}

func (c *Controller) decorateDebugWatchIdentity(result DebugWatchStartResult, packet *protocol.Packet) DebugWatchStartResult {
	ip := util.IpToUint32(packet.SrcIP)
	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
		client, ok := network.Clients[ip]
		if !ok {
			return true
		}
		authGroup := clientAuthGroup(client, network.Group)
		result.Group = authGroup
		result.Name = client.Name
		result.DeviceID = client.DeviceId
		result.VirtualIP = util.Uint32ToIP(ip).String()
		if userID := strings.TrimSpace(client.UserID); userID != "" {
			result.UserID = userID
		} else if userID, ok := c.userIDForAuthedDevice(authGroup, client.DeviceId); ok {
			result.UserID = userID
		}
		return false
	})
	return result
}

func (c *Controller) resolveDebugWatchStartFailure(result DebugWatchStartResult) {
	c.debugMu.Lock()
	waiter, ok := c.pendingDebugWatchStart[result.RequestID]
	if ok {
		delete(c.pendingDebugWatchStart, result.RequestID)
	}
	c.debugMu.Unlock()
	if ok {
		waiter <- result
	}
}

func (c *Controller) newDebugWatchStartWaiter() (uint64, chan DebugWatchStartResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	c.debugWatchSeq++
	requestID := c.debugWatchSeq
	waiter := make(chan DebugWatchStartResult, 1)
	c.pendingDebugWatchStart[requestID] = waiter
	return requestID, waiter
}

func (c *Controller) finishDebugWatchStartWaiter(requestID uint64, waiter chan DebugWatchStartResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	if current, ok := c.pendingDebugWatchStart[requestID]; ok && current == waiter {
		delete(c.pendingDebugWatchStart, requestID)
	}
}

func (c *Controller) cancelDebugWatchStart(requestID uint64) {
	c.debugMu.Lock()
	delete(c.pendingDebugWatchStart, requestID)
	c.debugMu.Unlock()
}

func (c *Controller) CancelDebugWatchStart(requestID uint64) {
	c.cancelDebugWatchStart(requestID)
}

func (c *Controller) newDebugWatchStopWaiter() (uint64, chan DebugWatchStopResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	c.debugWatchSeq++
	requestID := c.debugWatchSeq
	waiter := make(chan DebugWatchStopResult, 1)
	c.pendingDebugWatchStop[requestID] = waiter
	return requestID, waiter
}

func (c *Controller) finishDebugWatchStopWaiter(requestID uint64, waiter chan DebugWatchStopResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	if current, ok := c.pendingDebugWatchStop[requestID]; ok && current == waiter {
		delete(c.pendingDebugWatchStop, requestID)
	}
}

func (c *Controller) cancelDebugWatchStop(requestID uint64) {
	c.debugMu.Lock()
	delete(c.pendingDebugWatchStop, requestID)
	c.debugMu.Unlock()
}

func (c *Controller) CancelDebugWatchStop(requestID uint64) {
	c.cancelDebugWatchStop(requestID)
}

func (c *Controller) activeDebugWatchIDForDevice(deviceID string) uint64 {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	return c.activeDebugWatchByDevice[strings.TrimSpace(deviceID)]
}
