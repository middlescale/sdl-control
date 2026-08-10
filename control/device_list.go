package control

import (
	"sort"
	"strings"
	"time"

	"sdl-control/util"
)

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

	c.nc.forEachVirtualNetworkRead("", func(_ string, network *NetworkInfo) bool {
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
		return true
	})

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
