package control

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sdl-control/protocol/pb"
	"sort"
	"strings"
)

const (
	defaultDNSTTLSeconds   = 30
	defaultDNSRefreshAfter = 15
	implicitDNSGroupName   = "default"
)

type DNSSOAView struct {
	PrimaryNS    string `json:"primary_ns"`
	AdminMailbox string `json:"admin_mailbox"`
}

type DNSNetworkView struct {
	Group     string `json:"group"`
	GatewayIP string `json:"gateway_ip"`
	Netmask   string `json:"netmask"`
}

type DNSRecordView struct {
	FQDN               string `json:"fqdn"`
	ShortName          string `json:"short_name"`
	DeviceID           string `json:"device_id"`
	Group              string `json:"group"`
	VirtualIP          string `json:"virtual_ip"`
	ControlOnline      bool   `json:"control_online"`
	DataPlaneReachable bool   `json:"data_plane_reachable"`
	UpdatedAtUnix      int64  `json:"updated_at_unix"`
}

type DNSGatewayView struct {
	GatewayID string `json:"gateway_id"`
	Endpoint  string `json:"endpoint"`
	Default   bool   `json:"default"`
	Alive     bool   `json:"alive"`
}

type DNSSnapshotView struct {
	Domain            string           `json:"domain"`
	GroupFilter       string           `json:"group_filter,omitempty"`
	Epoch             uint64           `json:"epoch"`
	DefaultTTLSeconds uint32           `json:"default_ttl_seconds"`
	RefreshAfterSec   uint32           `json:"refresh_after_sec"`
	SOA               DNSSOAView       `json:"soa"`
	Networks          []DNSNetworkView `json:"networks,omitempty"`
	Records           []DNSRecordView  `json:"records,omitempty"`
	Gateways          []DNSGatewayView `json:"gateways,omitempty"`
}

type dnsGroupScope struct {
	shortName         string
	runtimeGroup      string
	gatewayIP         string
	netmask           string
	includeGroupLabel bool
}

func (c *Controller) ListDNSDomains() []string {
	domains := make([]string, 0, len(c.cfg.Domains))
	for domain := range c.cfg.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func (c *Controller) BuildDNSSnapshot(domain, group string) (*DNSSnapshotView, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	group = strings.ToLower(strings.TrimSpace(group))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(c.cfg.EffectiveDefaultDomain()))
	}
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	scopes, err := c.buildDNSGroupScopes(domain, group)
	if err != nil {
		return nil, err
	}

	snapshot := &DNSSnapshotView{
		Domain:            domain,
		GroupFilter:       group,
		DefaultTTLSeconds: defaultDNSTTLSeconds,
		RefreshAfterSec:   defaultDNSRefreshAfter,
		SOA: DNSSOAView{
			PrimaryNS:    "ns1." + domain,
			AdminMailbox: "admin." + domain,
		},
	}

	c.nc.VirtualNetwork.mutex.RLock()
	for _, scope := range scopes {
		snapshot.Networks = append(snapshot.Networks, DNSNetworkView{
			Group:     scope.shortName,
			GatewayIP: scope.gatewayIP,
			Netmask:   scope.netmask,
		})

		network, ok := c.nc.VirtualNetwork.data[scope.runtimeGroup]
		if !ok || network == nil {
			continue
		}
		for ip, client := range network.Clients {
			if strings.HasPrefix(clientNetworkScope(client, scope.runtimeGroup), personalNetworkPrefix) {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(client.Name))
			if name == "" {
				name = strings.ToLower(strings.TrimSpace(client.DeviceId))
			}
			updatedAt := client.ControlLastSeen
			if client.DataPlaneLastSeen > updatedAt {
				updatedAt = client.DataPlaneLastSeen
			}
			if client.LastJoin > updatedAt {
				updatedAt = client.LastJoin
			}
			snapshot.Records = append(snapshot.Records, DNSRecordView{
				FQDN:               buildDNSFQDN(name, scope.shortName, domain, scope.includeGroupLabel),
				ShortName:          name,
				DeviceID:           strings.TrimSpace(client.DeviceId),
				Group:              scope.shortName,
				VirtualIP:          net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String(),
				ControlOnline:      client.ControlOnline,
				DataPlaneReachable: client.DataPlaneReachable,
				UpdatedAtUnix:      updatedAt,
			})
		}
	}
	c.nc.VirtualNetwork.mutex.RUnlock()

	for _, gateway := range c.ListGateways() {
		snapshot.Gateways = append(snapshot.Gateways, DNSGatewayView{
			GatewayID: strings.TrimSpace(gateway.GatewayID),
			Endpoint:  strings.TrimSpace(gateway.Endpoint),
			Default:   gateway.Default,
			Alive:     gateway.Alive,
		})
	}

	sort.Slice(snapshot.Networks, func(i, j int) bool {
		return snapshot.Networks[i].Group < snapshot.Networks[j].Group
	})
	sort.Slice(snapshot.Records, func(i, j int) bool {
		if snapshot.Records[i].FQDN != snapshot.Records[j].FQDN {
			return snapshot.Records[i].FQDN < snapshot.Records[j].FQDN
		}
		if snapshot.Records[i].VirtualIP != snapshot.Records[j].VirtualIP {
			return snapshot.Records[i].VirtualIP < snapshot.Records[j].VirtualIP
		}
		return snapshot.Records[i].DeviceID < snapshot.Records[j].DeviceID
	})
	sort.Slice(snapshot.Gateways, func(i, j int) bool {
		return snapshot.Gateways[i].GatewayID < snapshot.Gateways[j].GatewayID
	})

	snapshot.Epoch = computeDNSEpoch(snapshot)
	return snapshot, nil
}

func (c *Controller) buildDNSGroupScopes(domain, group string) ([]dnsGroupScope, error) {
	if len(c.cfg.Domains) > 0 {
		dc, ok := c.cfg.Domains[domain]
		if !ok {
			return nil, fmt.Errorf("domain %s not configured", domain)
		}
		if group != "" {
			gc, ok := dc.Groups[group]
			if !ok {
				return nil, fmt.Errorf("group %s not configured under domain %s", group, domain)
			}
			return []dnsGroupScope{{
				shortName:         group,
				runtimeGroup:      group + "." + domain,
				gatewayIP:         gc.Gateway.String(),
				netmask:           gc.Netmask,
				includeGroupLabel: true,
			}}, nil
		}
		scopes := make([]dnsGroupScope, 0, len(dc.Groups))
		for groupName, gc := range dc.Groups {
			scopes = append(scopes, dnsGroupScope{
				shortName:         strings.ToLower(strings.TrimSpace(groupName)),
				runtimeGroup:      strings.ToLower(strings.TrimSpace(groupName)) + "." + domain,
				gatewayIP:         gc.Gateway.String(),
				netmask:           gc.Netmask,
				includeGroupLabel: true,
			})
		}
		return scopes, nil
	}

	if configured := strings.ToLower(strings.TrimSpace(c.cfg.Domain)); configured != "" {
		if domain != configured {
			return nil, fmt.Errorf("domain %s not configured", domain)
		}
		if group != "" && group != implicitDNSGroupName {
			return nil, fmt.Errorf("group %s not configured under domain %s", group, domain)
		}
		return []dnsGroupScope{{
			shortName:         implicitDNSGroupName,
			runtimeGroup:      configured,
			gatewayIP:         c.cfg.Gateway.String(),
			netmask:           c.cfg.Netmask,
			includeGroupLabel: false,
		}}, nil
	}

	return nil, fmt.Errorf("dns snapshot is unsupported for current control config")
}

func buildDNSFQDN(shortName, group, domain string, includeGroup bool) string {
	shortName = strings.ToLower(strings.TrimSpace(shortName))
	group = strings.ToLower(strings.TrimSpace(group))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if includeGroup && group != "" {
		return shortName + "." + group + "." + domain
	}
	return shortName + "." + domain
}

func computeDNSEpoch(snapshot *DNSSnapshotView) uint64 {
	h := sha256.New()
	writeLine := func(v string) {
		h.Write([]byte(v))
		h.Write([]byte{'\n'})
	}

	writeLine(snapshot.Domain)
	writeLine(snapshot.GroupFilter)
	writeLine(snapshot.SOA.PrimaryNS)
	writeLine(snapshot.SOA.AdminMailbox)
	writeLine(fmt.Sprintf("ttl:%d", snapshot.DefaultTTLSeconds))
	writeLine(fmt.Sprintf("refresh:%d", snapshot.RefreshAfterSec))
	for _, network := range snapshot.Networks {
		writeLine("net:" + network.Group + "|" + network.GatewayIP + "|" + network.Netmask)
	}
	for _, record := range snapshot.Records {
		writeLine("rec:" + record.FQDN + "|" + record.DeviceID + "|" + record.Group + "|" + record.VirtualIP)
	}
	sum := h.Sum(nil)
	epoch := binary.BigEndian.Uint64(sum[:8])
	if epoch == 0 {
		return 1
	}
	return epoch
}

func (c *Controller) BuildClientDNSProfile(token string) *pb.DnsProfile {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return nil
	}

	var servers []string
	var matchDomains []string

	switch {
	case len(c.cfg.Domains) > 0:
		domainName, groupName, ok := matchDomainAndGroup(token, c.cfg.Domains)
		if !ok {
			return nil
		}
		gc := c.cfg.Domains[domainName].Groups[groupName]
		servers = firstNonEmptyStrings(gc.DNSServers, c.cfg.DNSServers)
		if len(servers) == 0 {
			if serviceIP := c.resolveDNSServiceIP(token); serviceIP != "" {
				servers = []string{serviceIP}
			} else if gc.Gateway != nil {
				servers = []string{gc.Gateway.String()}
			}
		}
		matchDomains = firstNonEmptyStrings(gc.DNSMatchDomains, c.cfg.DNSMatchDomains)
		if len(matchDomains) == 0 {
			matchDomains = []string{domainName}
		}
		matchDomains = ensureGroupQualifiedMatchDomains(matchDomains, groupName, domainName)
	case len(c.cfg.Groups) > 0:
		gc, ok := c.cfg.Groups[token]
		if !ok {
			return nil
		}
		servers = firstNonEmptyStrings(gc.DNSServers, c.cfg.DNSServers)
		if len(servers) == 0 {
			if serviceIP := c.resolveDNSServiceIP(token); serviceIP != "" {
				servers = []string{serviceIP}
			} else if gc.Gateway != nil {
				servers = []string{gc.Gateway.String()}
			}
		}
		matchDomains = firstNonEmptyStrings(gc.DNSMatchDomains, c.cfg.DNSMatchDomains)
		if len(matchDomains) == 0 {
			matchDomains = []string{token}
		}
	default:
		domainName := strings.ToLower(strings.TrimSpace(c.cfg.EffectiveDefaultDomain()))
		if domainName == "" {
			return nil
		}
		servers = cloneStrings(c.cfg.DNSServers)
		if len(servers) == 0 {
			if serviceIP := c.resolveDNSServiceIP(token); serviceIP != "" {
				servers = []string{serviceIP}
			} else if c.cfg.Gateway != nil {
				servers = []string{c.cfg.Gateway.String()}
			}
		}
		matchDomains = cloneStrings(c.cfg.DNSMatchDomains)
		if len(matchDomains) == 0 {
			matchDomains = []string{domainName}
		}
	}

	servers = normalizeDNSStrings(servers, false)
	matchDomains = normalizeDNSStrings(matchDomains, true)
	if len(servers) == 0 || len(matchDomains) == 0 {
		return nil
	}
	return &pb.DnsProfile{
		Servers:      servers,
		MatchDomains: matchDomains,
	}
}

func ensureGroupQualifiedMatchDomains(domains []string, groupName, domainName string) []string {
	groupName = strings.ToLower(strings.TrimSpace(groupName))
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if groupName == "" || domainName == "" {
		return cloneStrings(domains)
	}
	qualified := groupName + "." + domainName
	out := cloneStrings(domains)
	for _, domain := range out {
		if strings.EqualFold(strings.TrimSpace(domain), qualified) {
			return out
		}
	}
	return append(out, qualified)
}

func firstNonEmptyStrings(primary, fallback []string) []string {
	if len(primary) > 0 {
		return cloneStrings(primary)
	}
	return cloneStrings(fallback)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func normalizeDNSStrings(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
