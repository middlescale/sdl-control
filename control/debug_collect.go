package control

import (
	"fmt"
	"net"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type DebugCollectResult struct {
	RequestID         uint64
	UserID            string
	Group             string
	Name              string
	DeviceID          string
	VirtualIP         string
	CollectedAtUnixMs int64
	SnapshotJSON      string
	SavedPath         string
}

func (c *Controller) PrepareDebugCollectByName(name, userID, group string, sections []string) (*protocol.Packet, uint32, uint64, error) {
	match, ip, networkKey, err := c.findOnlineDeviceByName(name, userID, group)
	if err != nil {
		return nil, 0, 0, err
	}
	requestID, waiter := c.newDebugCollectWaiter()
	req := &pb.DebugCollectRequest{
		RequestId: requestID,
		Sections:  normalizeDebugSections(sections),
		Reason:    "admin collect_debug",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		c.finishDebugCollectWaiter(requestID, waiter)
		return nil, 0, 0, err
	}
	packet := &protocol.Packet{
		Ver:             protocol.V3,
		Proto:           protocol.ProtocolService,
		AppProto:        protocol.AppProtoDebugCollectRequest,
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

func (c *Controller) AwaitDebugCollect(requestID uint64, timeout time.Duration) (DebugCollectResult, error) {
	c.debugMu.Lock()
	waiter, ok := c.pendingDebugCollect[requestID]
	c.debugMu.Unlock()
	if !ok {
		return DebugCollectResult{}, fmt.Errorf("debug request %d not found", requestID)
	}
	select {
	case result := <-waiter:
		if result.SnapshotJSON == "" {
			return DebugCollectResult{}, fmt.Errorf("debug collection returned empty snapshot")
		}
		return result, nil
	case <-time.After(timeout):
		c.CancelDebugCollect(requestID)
		return DebugCollectResult{}, fmt.Errorf("debug collection timed out")
	}
}

func (c *Controller) CancelDebugCollect(requestID uint64) {
	c.debugMu.Lock()
	delete(c.pendingDebugCollect, requestID)
	c.debugMu.Unlock()
}

func (c *Controller) HandleDebugCollectResponse(request *protocol.Packet) error {
	var resp pb.DebugCollectResponse
	if err := proto.Unmarshal(request.Payload, &resp); err != nil {
		return err
	}
	result := c.decorateDebugCollectResult(request, &resp)
	if !resp.GetOk() {
		if strings.TrimSpace(resp.GetReason()) != "" {
			result.SnapshotJSON = fmt.Sprintf("{\"error\":%q}", strings.TrimSpace(resp.GetReason()))
		} else {
			result.SnapshotJSON = "{\"error\":\"debug collection rejected\"}"
		}
	}
	c.resolveDebugCollect(result)
	return nil
}

func (c *Controller) resolveDebugCollect(result DebugCollectResult) {
	if c.debugStore != nil && strings.TrimSpace(result.SnapshotJSON) != "" {
		savedPath, err := c.debugStore.Save(result)
		if err != nil {
			log.Warnf("persist debug snapshot failed request_id=%d err=%v", result.RequestID, err)
		} else {
			result.SavedPath = savedPath
		}
	}
	c.debugMu.Lock()
	waiter, ok := c.pendingDebugCollect[result.RequestID]
	if ok {
		delete(c.pendingDebugCollect, result.RequestID)
	}
	if result.DeviceID != "" {
		c.latestDebugCollect[result.DeviceID] = result
	}
	c.debugMu.Unlock()
	if ok {
		waiter <- result
	}
}

func (c *Controller) decorateDebugCollectResult(packet *protocol.Packet, resp *pb.DebugCollectResponse) DebugCollectResult {
	result := DebugCollectResult{
		RequestID:         resp.GetRequestId(),
		CollectedAtUnixMs: resp.GetCollectedAtUnixMs(),
		SnapshotJSON:      resp.GetSnapshotJson(),
		VirtualIP:         packet.SrcIP.String(),
	}
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

func (c *Controller) findOnlineDeviceByName(name, userID, group string) (DeviceAdminView, uint32, string, error) {
	name = strings.TrimSpace(name)
	userID = strings.TrimSpace(userID)
	group = strings.TrimSpace(group)
	if name == "" {
		return DeviceAdminView{}, 0, "", fmt.Errorf("name required")
	}
	type match struct {
		view       DeviceAdminView
		ip         uint32
		networkKey string
	}
	var matches []match
	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
		for ip, client := range network.Clients {
			authGroup := clientAuthGroup(client, network.Group)
			if group != "" && !strings.EqualFold(authGroup, group) {
				continue
			}
			if !client.ControlOnline || !strings.EqualFold(strings.TrimSpace(client.Name), name) {
				continue
			}
			recordUserID := strings.TrimSpace(client.UserID)
			if recordUserID == "" {
				recordUserID, _ = c.userIDForAuthedDevice(authGroup, client.DeviceId)
			}
			if userID != "" && !strings.EqualFold(recordUserID, userID) {
				continue
			}
			matches = append(matches, match{
				ip:         ip,
				networkKey: clientNetworkKey(client, network.Group),
				view: DeviceAdminView{
					UserID:             recordUserID,
					Group:              authGroup,
					Name:               client.Name,
					DeviceID:           client.DeviceId,
					VirtualIP:          util.Uint32ToIP(ip).String(),
					ControlOnline:      client.ControlOnline,
					DataPlaneReachable: client.DataPlaneReachable,
				},
			})
		}
		return true
	})
	if len(matches) == 0 {
		return DeviceAdminView{}, 0, "", fmt.Errorf("no online device matched name %q", name)
	}
	if len(matches) > 1 {
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].view.Group != matches[j].view.Group {
				return matches[i].view.Group < matches[j].view.Group
			}
			if matches[i].view.UserID != matches[j].view.UserID {
				return matches[i].view.UserID < matches[j].view.UserID
			}
			return matches[i].view.DeviceID < matches[j].view.DeviceID
		})
		items := make([]string, 0, len(matches))
		for _, item := range matches {
			items = append(items, fmt.Sprintf("%s/%s/%s", item.view.UserID, item.view.Group, item.view.DeviceID))
		}
		return DeviceAdminView{}, 0, "", fmt.Errorf("name %q matched multiple online devices: %s", name, strings.Join(items, ", "))
	}
	return matches[0].view, matches[0].ip, matches[0].networkKey, nil
}

func (c *Controller) userIDForAuthedDevice(groupName, deviceID string) (string, bool) {
	c.um.mu.RLock()
	defer c.um.mu.RUnlock()
	record, ok := c.um.authedDevices[groupName+"\x00"+deviceID]
	if !ok {
		return "", false
	}
	return record.UserID, true
}

func (c *Controller) newDebugCollectWaiter() (uint64, chan DebugCollectResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	c.debugCollectSeq++
	requestID := c.debugCollectSeq
	waiter := make(chan DebugCollectResult, 1)
	c.pendingDebugCollect[requestID] = waiter
	return requestID, waiter
}

func (c *Controller) finishDebugCollectWaiter(requestID uint64, waiter chan DebugCollectResult) {
	c.debugMu.Lock()
	defer c.debugMu.Unlock()
	if current, ok := c.pendingDebugCollect[requestID]; ok && current == waiter {
		delete(c.pendingDebugCollect, requestID)
	}
}

func normalizeDebugSections(sections []string) []string {
	if len(sections) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(sections))
	for _, section := range sections {
		normalized := strings.ToLower(strings.TrimSpace(section))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}
