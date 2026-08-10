package control

import (
	"fmt"
	"net"
	"strings"
	"time"

	"sdl-control/protocol/pb"
	"sdl-control/util"
)

type NetworkControl struct {
	//
	VirtualNetwork ExpireMap[string, *NetworkInfo]
	// 用来做地址分配和回收
	IPSessions ExpireMap[IpSessionKey, net.Addr]
	// 链路上的加密会话上下文占位（按远端地址跟踪）
	CipherSessions ExpireMap[string, struct{}]
	// 打洞会话状态（session_id + attempt）
	PunchSessions ExpireMap[string, *PunchSession]
	// 打洞触发冷却（pair key）
	PunchPairCooldown ExpireMap[string, struct{}]
	// Manual recovery de-duplication for simultaneous bidirectional payload.
	ManualPunchPairDedup ExpireMap[string, struct{}]
	// 打洞重试状态（pair key）
	PunchPairRetry ExpireMap[string, PunchRetryState]
}

func (nc *NetworkControl) forEachVirtualNetworkRead(networkKey string, visit func(key string, network *NetworkInfo) bool) {
	if visit == nil {
		return
	}
	networkKey = strings.TrimSpace(networkKey)
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	for key, network := range nc.VirtualNetwork.data {
		if networkKey != "" && key != networkKey {
			continue
		}
		if !visit(key, network) {
			return
		}
	}
}

// IpSessionKey is a comparable key for IPSessions.
// Use string fields because net.IP (a []byte) is not comparable.
type IpSessionKey struct {
	ID string // domain
	IP string // use net.IP.String()
}

// compile-time check: ensure IpSessionKey is comparable (map key). If IpSessionKey contains
// a non-comparable field (e.g. slice), this will fail to compile.
var _ map[IpSessionKey]struct{} = nil

// NewIpSessionKey builds an IpSessionKey from an id and net.IP.
func NewIpSessionKey(id string, ip net.IP) IpSessionKey {
	return IpSessionKey{
		ID: id,
		IP: ip.String(),
	}
}

func networkScopeForAuth(groupName, userID string) string {
	return NewNetworkIdentity(groupName, userID).Scope()
}

func isPersonalSDLUser(userID string) bool {
	return strings.HasPrefix(strings.TrimSpace(userID), personalUserIDPrefix)
}

func clientAuthGroup(client ClientInfo, fallback string) string {
	return NetworkIdentityFromClient(client, fallback).AuthGroup()
}

func clientNetworkKey(client ClientInfo, fallback string) string {
	return NetworkIdentityFromClient(client, fallback).Key()
}

func clientNetworkScope(client ClientInfo, fallbackGroup string) string {
	return NetworkIdentityFromClient(client, fallbackGroup).Scope()
}

func parseNetmask(netmask string) (net.IPMask, error) {
	ip := net.ParseIP(netmask)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid netmask %q", netmask)
	}
	return net.IPMask(ip.To4()), nil
}

func (nc *NetworkControl) generateIP(
	network *NetworkInfo,
	requestedIP uint32,
	deviceID string,
	allowIPChange bool,
) (virtualIP uint32, oldIP uint32, err error) {
	oldIP = network.FindClientIPByDeviceID(deviceID)
	if requestedIP != 0 {
		if err = validateRequestedIP(requestedIP, network.Gateway, network.Netmask); err != nil {
			return 0, oldIP, err
		}
		if current, ok := network.Clients[requestedIP]; ok && current.DeviceId != deviceID {
			if !allowIPChange {
				return 0, oldIP, fmt.Errorf("virtual ip %s already in use", util.Uint32ToIP(requestedIP))
			}
			requestedIP = 0
		}
	}
	if requestedIP != 0 {
		return requestedIP, oldIP, nil
	}
	if oldIP != 0 {
		return oldIP, oldIP, nil
	}
	networkIP := util.IpToUint32(network.Gateway) & util.MaskToUint32(network.Netmask)
	mask := util.MaskToUint32(network.Netmask)
	broadcast := networkIP | ^mask
	gatewayIP := util.IpToUint32(network.Gateway)

	// first and last usable (exclude network and broadcast)
	first := networkIP + 1
	last := broadcast - 1
	if first > last {
		return 0, 0, fmt.Errorf("no available virtual ips")
	}
	for ip := first; ip <= last; ip++ {
		if ip == gatewayIP {
			continue
		}
		if _, reserved := network.ReservedIPs[ip]; reserved {
			continue
		}
		if client, occupied := network.Clients[ip]; occupied {
			if !client.ControlOnline {
				key := NewIpSessionKey(network.Group, util.Uint32ToIP(ip))
				if _, reserved := nc.IPSessions.Get(key); !reserved {
					network.DeleteClient(ip)
				} else {
					continue
				}
			} else {
				continue
			}
		}
		candidate := util.Uint32ToIP(ip)
		key := NewIpSessionKey(network.Group, candidate)
		if _, occupied := nc.IPSessions.Get(key); !occupied {
			addr := &net.IPAddr{IP: candidate}
			nc.IPSessions.Set(key, addr)
			return ip, 0, nil
		}
	}
	return 0, 0, fmt.Errorf("no available virtual ips")
}

func (nc *NetworkControl) TouchClientByIP(srcIP net.IP) uint16 {
	return nc.TouchClientByIPInNetwork("", srcIP)
}

func (nc *NetworkControl) TouchClientByIPInNetwork(networkKey string, srcIP net.IP) uint16 {
	ip := util.IpToUint32(srcIP)
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	now := time.Now().Unix()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		if client, ok := network.Clients[ip]; ok {
			client.ControlOnline = true
			client.ControlLastSeen = now
			network.UpsertClient(ip, client)
			return uint16(network.Epoch)
		}
	}
	return 0
}

func (c *Controller) TouchCipherSession(remoteAddr net.Addr) {
	c.nc.TouchCipherSession(remoteAddr)
}

func (nc *NetworkControl) TouchCipherSession(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	nc.CipherSessions.Set(remoteAddr.String(), struct{}{})
}

func (c *Controller) LeaveByRemoteAddr(remoteAddr net.Addr) {
	c.clearPendingHandshakeCapabilities(remoteAddr)
	c.nc.LeaveByRemoteAddr(remoteAddr)
}

func (nc *NetworkControl) LeaveByRemoteAddr(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	addr := remoteAddr.String()
	nc.CipherSessions.Delete(addr)
	now := time.Now().Unix()
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for _, network := range nc.VirtualNetwork.data {
		changed := false
		for ip, client := range network.Clients {
			if client.Address == nil || client.Address.String() != addr || !client.ControlOnline {
				continue
			}
			client.ControlOnline = false
			client.ControlLastSeen = now
			client.DataPlaneReachable = false
			client.DataPlaneLastSeen = 0
			client.ClientStatus = nil
			client.PreferredChannelMode = pb.ChannelMode_CHANNEL_MODE_AUTO
			network.UpsertClient(ip, client)
			nc.IPSessions.Set(NewIpSessionKey(network.Group, util.Uint32ToIP(ip)), remoteAddr)
			changed = true
		}
		if changed {
			network.Epoch++
		}
	}
}

func (nc *NetworkControl) DeviceListByIP(selfIP uint32) (*pb.DeviceList, bool) {
	return nc.DeviceListByIPInNetwork("", selfIP)
}

func (nc *NetworkControl) DeviceListByIPInNetwork(networkKey string, selfIP uint32) (*pb.DeviceList, bool) {
	var deviceList *pb.DeviceList
	nc.forEachVirtualNetworkRead(networkKey, func(_ string, network *NetworkInfo) bool {
		if _, ok := network.Clients[selfIP]; !ok {
			return true
		}
		deviceList = &pb.DeviceList{
			Epoch:          uint32(network.Epoch),
			DeviceInfoList: buildDeviceInfoList(network.Clients, selfIP),
		}
		return false
	})
	return deviceList, deviceList != nil
}

func (nc *NetworkControl) FindClientByVirtualIP(virtualIP uint32) (ClientInfo, bool) {
	return nc.FindClientByVirtualIPInNetwork("", virtualIP)
}

func (nc *NetworkControl) FindClientByVirtualIPInNetwork(networkKey string, virtualIP uint32) (ClientInfo, bool) {
	var found ClientInfo
	foundOK := false
	nc.forEachVirtualNetworkRead(networkKey, func(_ string, network *NetworkInfo) bool {
		client, ok := network.Clients[virtualIP]
		if ok {
			found = client
			foundOK = true
			return false
		}
		return true
	})
	return found, foundOK
}

func (nc *NetworkControl) FindClientByDeviceID(groupName string, deviceID string) (ClientInfo, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	network, ok := nc.VirtualNetwork.data[groupName]
	if !ok {
		for _, network := range nc.VirtualNetwork.data {
			for _, client := range network.Clients {
				if client.DeviceId == deviceID && strings.EqualFold(clientAuthGroup(client, network.Group), groupName) {
					return client, true
				}
			}
		}
		return ClientInfo{}, false
	}
	virtualIP := network.FindClientIPByDeviceID(deviceID)
	if virtualIP != 0 {
		if client, ok := network.Clients[virtualIP]; ok {
			return client, true
		}
	}
	for _, client := range network.Clients {
		if client.DeviceId == deviceID {
			return client, true
		}
	}
	return ClientInfo{}, false
}

func (nc *NetworkControl) UpdateClientByVirtualIP(virtualIP uint32, update func(*ClientInfo)) bool {
	return nc.UpdateClientByVirtualIPInNetwork("", virtualIP, update)
}

func (nc *NetworkControl) UpdateClientByVirtualIPInNetwork(networkKey string, virtualIP uint32, update func(*ClientInfo)) bool {
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for key, network := range nc.VirtualNetwork.data {
		if strings.TrimSpace(networkKey) != "" && key != networkKey {
			continue
		}
		client, ok := network.Clients[virtualIP]
		if !ok {
			continue
		}
		update(&client)
		network.UpsertClient(virtualIP, client)
		return true
	}
	return false
}

func (nc *NetworkControl) FindPunchSession(sessionID uint64, attempt uint32) (*PunchSession, bool) {
	return nc.PunchSessions.Get(punchSessionKey(sessionID, attempt))
}
func (c *Controller) clientOwnsVirtualIP(virtualIP uint32, deviceID string) bool {
	return c.clientOwnsVirtualIPInNetwork("", virtualIP, deviceID)
}

func (c *Controller) clientOwnsVirtualIPInNetwork(networkKey string, virtualIP uint32, deviceID string) bool {
	owns := false
	c.nc.forEachVirtualNetworkRead(networkKey, func(_ string, network *NetworkInfo) bool {
		if client, ok := network.Clients[virtualIP]; ok {
			owns = client.DeviceId == deviceID
			return false
		}
		return true
	})
	return owns
}
