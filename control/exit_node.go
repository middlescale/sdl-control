package control

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"sdl-control/protocol/pb"
	"sdl-control/util"
)

func (c *Controller) ApproveExitNode(userID, deviceID string) error {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if deviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if !c.isAuthedDeviceForUser(userID, deviceID) {
		return fmt.Errorf("device %s is not authed for user %s", deviceID, userID)
	}
	if c.pgStore == nil {
		return fmt.Errorf("exit-node approval requires DATABASE_URL")
	}
	c.exitNodeMu.Lock()
	defer c.exitNodeMu.Unlock()
	if err := c.pgStore.ApproveExitNode(userID, deviceID, "sdl-admin"); err != nil {
		return err
	}
	if c.exitNodeApproved[userID] == nil {
		c.exitNodeApproved[userID] = map[string]bool{}
	}
	c.exitNodeApproved[userID][deviceID] = true
	return nil
}

// ApproveExitNodeTarget resolves an authenticated device by its stable ID, or by
// its display name within an explicitly supplied user, then records its approval.
func (c *Controller) ApproveExitNodeTarget(userID, deviceID, displayName string) (string, string, error) {
	userID, deviceID, err := c.resolveExitNodeApprovalTarget(userID, deviceID, displayName)
	if err != nil {
		return "", "", err
	}
	if err := c.ApproveExitNode(userID, deviceID); err != nil {
		return "", "", err
	}
	return userID, deviceID, nil
}

func (c *Controller) resolveExitNodeApprovalTarget(userID, deviceID, displayName string) (string, string, error) {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	displayName = strings.TrimSpace(displayName)
	if deviceID != "" && displayName != "" {
		return "", "", fmt.Errorf("specify either device_id or name, not both")
	}
	if deviceID == "" && displayName == "" {
		return "", "", fmt.Errorf("device_id or name is required")
	}
	if displayName != "" && userID == "" {
		return "", "", fmt.Errorf("user_id is required when approving by name")
	}

	records := c.um.ListAuthedDevices()
	if userID != "" {
		records = c.um.ListAuthedDevicesByUser(userID)
	}
	matches := make([]UMAuthDevice, 0, 1)
	for _, record := range records {
		if (deviceID != "" && record.DeviceID == deviceID) ||
			(displayName != "" && record.DisplayName == displayName) {
			matches = append(matches, record)
		}
	}
	if len(matches) == 0 {
		if userID != "" {
			if displayName != "" {
				return "", "", fmt.Errorf("node %q is not authed for user %s", displayName, userID)
			}
			return "", "", fmt.Errorf("device %s is not authed for user %s", deviceID, userID)
		}
		return "", "", fmt.Errorf("device %s is not an authed device", deviceID)
	}
	if len(matches) > 1 {
		if userID == "" {
			return "", "", fmt.Errorf("device %s is ambiguous; specify --id/-u <user-id>", deviceID)
		}
		return "", "", fmt.Errorf("node %q is ambiguous for user %s; use its device_id", displayName, userID)
	}
	match := matches[0]
	return match.UserID, match.DeviceID, nil
}

func (c *Controller) RevokeExitNode(userID, deviceID string) error {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if deviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if c.pgStore == nil {
		return fmt.Errorf("exit-node approval requires DATABASE_URL")
	}
	c.exitNodeMu.Lock()
	defer c.exitNodeMu.Unlock()
	devices := c.exitNodeApproved[userID]
	if len(devices) == 0 || !devices[deviceID] {
		return fmt.Errorf("exit node %s for user %s is not approved", deviceID, userID)
	}
	if err := c.pgStore.RevokeExitNode(userID, deviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("exit node %s for user %s is not approved", deviceID, userID)
		}
		return err
	}
	delete(devices, deviceID)
	if len(devices) == 0 {
		delete(c.exitNodeApproved, userID)
	}
	return nil
}

func (c *Controller) ListExitNodes(userID string) []ExitNodeAdminView {
	userID = strings.TrimSpace(userID)
	c.exitNodeMu.RLock()
	approved := make(map[string]map[string]bool, len(c.exitNodeApproved))
	for approvedUserID, devices := range c.exitNodeApproved {
		if userID != "" && approvedUserID != userID {
			continue
		}
		approved[approvedUserID] = make(map[string]bool, len(devices))
		for deviceID, ok := range devices {
			if ok {
				approved[approvedUserID][deviceID] = true
			}
		}
	}
	c.exitNodeMu.RUnlock()

	records := c.um.ListAuthedDevices()
	if userID != "" {
		records = c.um.ListAuthedDevicesByUser(userID)
	}
	viewsByKey := make(map[string]ExitNodeAdminView)
	for _, record := range records {
		if userID != "" && record.UserID != userID {
			continue
		}
		isApproved := approved[record.UserID][record.DeviceID]
		if !isApproved {
			continue
		}
		name := strings.TrimSpace(record.DisplayName)
		if name == "" {
			name = record.DeviceID
		}
		key := record.UserID + "\x00" + record.DeviceID
		viewsByKey[key] = ExitNodeAdminView{
			UserID:   record.UserID,
			Group:    record.GroupName,
			Name:     name,
			DeviceID: record.DeviceID,
			Approved: isApproved,
		}
	}
	for approvedUserID, devices := range approved {
		for deviceID := range devices {
			key := approvedUserID + "\x00" + deviceID
			if _, ok := viewsByKey[key]; ok {
				continue
			}
			viewsByKey[key] = ExitNodeAdminView{
				UserID:   approvedUserID,
				DeviceID: deviceID,
				Approved: true,
			}
		}
	}
	c.mergeExitNodeRuntimeViews(viewsByKey, userID)

	views := make([]ExitNodeAdminView, 0, len(viewsByKey))
	for _, view := range viewsByKey {
		view.Usable = view.Approved && view.Advertised && view.LocalReady && view.ControlOnline
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].UserID != views[j].UserID {
			return views[i].UserID < views[j].UserID
		}
		if views[i].Group != views[j].Group {
			return views[i].Group < views[j].Group
		}
		if views[i].Name != views[j].Name {
			return views[i].Name < views[j].Name
		}
		return views[i].DeviceID < views[j].DeviceID
	})
	return views
}

func (c *Controller) exitNodeApprovedSnapshot() map[string]map[string]bool {
	c.exitNodeMu.RLock()
	defer c.exitNodeMu.RUnlock()
	approved := make(map[string]map[string]bool, len(c.exitNodeApproved))
	for userID, devices := range c.exitNodeApproved {
		approved[userID] = make(map[string]bool, len(devices))
		for deviceID, ok := range devices {
			if ok {
				approved[userID][deviceID] = true
			}
		}
	}
	return approved
}

func (c *Controller) enrichDeviceInfoListExitNodes(networkKey string, items []*pb.DeviceInfo) {
	if len(items) == 0 {
		return
	}
	clientsByIP := map[uint32]ClientInfo{}
	c.nc.forEachVirtualNetworkRead(networkKey, func(_ string, network *NetworkInfo) bool {
		for ip, client := range network.Clients {
			clientsByIP[ip] = client
		}
		return strings.TrimSpace(networkKey) == ""
	})
	c.enrichDeviceInfoListExitNodesFromClients(items, clientsByIP)
}

func (c *Controller) enrichDeviceInfoListExitNodesFromClients(items []*pb.DeviceInfo, clientsByIP map[uint32]ClientInfo) {
	if len(items) == 0 {
		return
	}
	approved := c.exitNodeApprovedSnapshot()
	for _, item := range items {
		if item == nil {
			continue
		}
		client, ok := clientsByIP[item.GetVirtualIp()]
		if !ok {
			continue
		}
		isApproved := approved[client.UserID][client.DeviceId]
		item.ExitNodeAdvertised = clientExitNodeAdvertised(client)
		item.ExitNodeApproved = isApproved
		item.ExitNodeUsable = isApproved && clientExitNodeUsable(client)
	}
}

func (c *Controller) isAuthedDeviceForUser(userID, deviceID string) bool {
	for _, record := range c.um.ListAuthedDevicesByUser(userID) {
		if record.DeviceID == deviceID {
			return true
		}
	}
	return false
}

func (c *Controller) mergeExitNodeRuntimeViews(viewsByKey map[string]ExitNodeAdminView, userIDFilter string) {
	userIDFilter = strings.TrimSpace(userIDFilter)
	approved := c.exitNodeApprovedSnapshot()
	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
		for ip, client := range network.Clients {
			if userIDFilter != "" && client.UserID != userIDFilter {
				continue
			}
			key := client.UserID + "\x00" + client.DeviceId
			view, ok := viewsByKey[key]
			isApproved := approved[client.UserID][client.DeviceId]
			if !ok && !isApproved && !clientExitNodeAdvertised(client) && !clientExitNodeLocalReady(client) {
				continue
			}
			if !ok {
				view = ExitNodeAdminView{
					UserID:   client.UserID,
					DeviceID: client.DeviceId,
					Approved: isApproved,
				}
			}
			if strings.TrimSpace(client.Name) != "" {
				view.Name = client.Name
			}
			if strings.TrimSpace(view.Group) == "" {
				view.Group = clientAuthGroup(client, network.Group)
			}
			view.VirtualIP = util.Uint32ToIP(ip).String()
			view.Advertised = clientExitNodeAdvertised(client)
			view.Approved = isApproved
			view.LocalReady = clientExitNodeLocalReady(client)
			view.ControlOnline = client.ControlOnline
			view.DataPlaneReachable = client.DataPlaneReachable
			updatedAt := client.ControlLastSeen
			if client.DataPlaneLastSeen > updatedAt {
				updatedAt = client.DataPlaneLastSeen
			}
			if client.LastJoin > updatedAt {
				updatedAt = client.LastJoin
			}
			if updatedAt > view.UpdatedAtUnix {
				view.UpdatedAtUnix = updatedAt
			}
			viewsByKey[key] = view
		}
		return true
	})
}

func clientExitNodeAdvertised(client ClientInfo) bool {
	return client.ClientStatus != nil && client.ClientStatus.ExitNodeAdvertised
}

func clientExitNodeLocalReady(client ClientInfo) bool {
	return client.ClientStatus != nil && client.ClientStatus.ExitNodeLocalReady
}

func clientExitNodeUsable(client ClientInfo) bool {
	return client.ControlOnline && clientExitNodeAdvertised(client) && clientExitNodeLocalReady(client)
}
