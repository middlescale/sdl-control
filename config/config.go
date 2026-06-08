package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
)

// Config 配置结构体
// gateway: IPv4 地址
// netmask: IPv4 子网掩码
// domain: 域名字符串
type Config struct {
	Gateway                   net.IP                  `json:"gateway"`
	Domain                    string                  `json:"domain"`
	Netmask                   string                  `json:"netmask"`
	DNSServiceIP              string                  `json:"dns_service_ip,omitempty"`
	DNSServers                []string                `json:"dns_servers,omitempty"`
	DNSMatchDomains           []string                `json:"dns_match_domains,omitempty"`
	Groups                    map[string]GroupConfig  `json:"groups"`
	DefaultDomain             string                  `json:"default_domain"`
	Domains                   map[string]DomainConfig `json:"domains"`
	DefaultGatewayID          string                  `json:"default_gateway_id"`
	GatewayTicketSecret       string                  `json:"gateway_ticket_secret"`
	DNSServiceAddr            string                  `json:"dns_service_addr,omitempty"`
	ListenAddr                string                  `json:"listen_addr"`
	AdminHTTPAddr             string                  `json:"admin_http_addr,omitempty"`
	AdminHTTPToken            string                  `json:"admin_http_token,omitempty"`
	DatabaseURL               string                  `json:"database_url,omitempty"`
	AutoCertDomain            string                  `json:"autocert_domain"`
	AutoCertHTTPAddr          string                  `json:"autocert_http_addr"`
	AutoCertEmail             string                  `json:"autocert_email"`
	CertCacheDir              string                  `json:"cert_cache_dir"`
	TLSCertPath               string                  `json:"tls_cert_path"`
	TLSKeyPath                string                  `json:"tls_key_path"`
	ClientCAPath              string                  `json:"client_ca_path"`
	RequireClientCert         bool                    `json:"require_client_cert"`
	DebugCollectDir           string                  `json:"debug_collect_dir,omitempty"`
	DebugCollectKeepPerDevice int                     `json:"debug_collect_keep_per_device,omitempty"`
}

const defaultGatewayID = "default"

type GroupConfig struct {
	Gateway         net.IP   `json:"gateway"`
	Netmask         string   `json:"netmask"`
	DNSServiceIP    string   `json:"dns_service_ip,omitempty"`
	DNSServers      []string `json:"dns_servers,omitempty"`
	DNSMatchDomains []string `json:"dns_match_domains,omitempty"`
}

type DomainConfig struct {
	Groups map[string]GroupConfig `json:"groups"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate 校验配置字段格式
func (c *Config) Validate() error {
	if strings.TrimSpace(c.DefaultGatewayID) == "" {
		c.DefaultGatewayID = defaultGatewayID
	}
	if strings.TrimSpace(c.GatewayTicketSecret) == "" {
		return errors.New("gateway_ticket_secret 不能为空")
	}
	if strings.TrimSpace(c.DNSServiceAddr) == "" {
		c.DNSServiceAddr = "127.0.0.1:53"
	}
	if _, _, err := net.SplitHostPort(c.DNSServiceAddr); err != nil {
		return errors.New("dns_service_addr 必须为 host:port")
	}
	if strings.TrimSpace(c.AutoCertHTTPAddr) == "" {
		c.AutoCertHTTPAddr = ":80"
	}
	// 域名校验（简单正则，支持主流域名）
	domainRe := regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	groupRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)
	if len(c.Domains) > 0 {
		if err := validateDNSServers(c.DNSServers); err != nil {
			return err
		}
		if err := validateServiceIP(c.DNSServiceIP, c.Gateway, c.Netmask, "dns_service_ip"); err != nil {
			return err
		}
		if err := validateDNSMatchDomains(c.DNSMatchDomains, domainRe); err != nil {
			return err
		}
		if strings.TrimSpace(c.DefaultDomain) == "" {
			c.DefaultDomain = "ms.net"
		}
		if !domainRe.MatchString(c.DefaultDomain) {
			return errors.New("default_domain 必须为合法域名")
		}
		if _, ok := c.Domains[c.DefaultDomain]; !ok {
			return errors.New("default_domain 未在 domains 中配置")
		}
		for domain, dc := range c.Domains {
			if !domainRe.MatchString(domain) {
				return errors.New("domains 的 key 必须为合法域名(FQDN)")
			}
			if len(dc.Groups) == 0 {
				return errors.New("domains.<domain>.groups 不能为空")
			}
			for group, gc := range dc.Groups {
				if !groupRe.MatchString(group) {
					return errors.New("domains.<domain>.groups 的 key 必须为合法 group 名称")
				}
				if err := validateGatewayAndNetmask(gc.Gateway, gc.Netmask); err != nil {
					return err
				}
				if err := validateServiceIP(gc.DNSServiceIP, gc.Gateway, gc.Netmask, "domains.<domain>.groups.<group>.dns_service_ip"); err != nil {
					return err
				}
				if err := validateDNSServers(gc.DNSServers); err != nil {
					return err
				}
				if err := validateDNSMatchDomains(gc.DNSMatchDomains, domainRe); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if len(c.Groups) == 0 {
		if err := validateGatewayAndNetmask(c.Gateway, c.Netmask); err != nil {
			return err
		}
		if err := validateServiceIP(c.DNSServiceIP, c.Gateway, c.Netmask, "dns_service_ip"); err != nil {
			return err
		}
		if err := validateDNSServers(c.DNSServers); err != nil {
			return err
		}
		if err := validateDNSMatchDomains(c.DNSMatchDomains, domainRe); err != nil {
			return err
		}
		if !domainRe.MatchString(c.Domain) {
			return errors.New("domain 必须为合法域名")
		}
		return nil
	}
	for group, gc := range c.Groups {
		if !domainRe.MatchString(group) {
			return errors.New("groups 的 key 必须为合法域名")
		}
		if err := validateGatewayAndNetmask(gc.Gateway, gc.Netmask); err != nil {
			return err
		}
		if err := validateServiceIP(gc.DNSServiceIP, gc.Gateway, gc.Netmask, "groups.<group>.dns_service_ip"); err != nil {
			return err
		}
		if err := validateDNSServers(gc.DNSServers); err != nil {
			return err
		}
		if err := validateDNSMatchDomains(gc.DNSMatchDomains, domainRe); err != nil {
			return err
		}
	}
	if c.Domain != "" {
		if !domainRe.MatchString(c.Domain) {
			return errors.New("domain 必须为合法域名")
		}
		if err := validateGatewayAndNetmask(c.Gateway, c.Netmask); err != nil {
			return err
		}
	}
	if err := validateServiceIP(c.DNSServiceIP, c.Gateway, c.Netmask, "dns_service_ip"); err != nil {
		return err
	}
	if err := validateDNSServers(c.DNSServers); err != nil {
		return err
	}
	if err := validateDNSMatchDomains(c.DNSMatchDomains, domainRe); err != nil {
		return err
	}
	return nil
}

func (c *Config) EffectiveDefaultDomain() string {
	if strings.TrimSpace(c.DefaultDomain) != "" {
		return c.DefaultDomain
	}
	if strings.TrimSpace(c.Domain) != "" {
		return c.Domain
	}
	for domain := range c.Domains {
		return domain
	}
	return ""
}

func validateGatewayAndNetmask(gateway net.IP, netmaskStr string) error {
	if gateway == nil || gateway.To4() == nil {
		return errors.New("gateway 必须为合法 IPv4 地址")
	}
	if gateway.To4()[3] == 255 {
		return errors.New("gateway 不能为广播地址")
	}
	if gateway.To4()[0] >= 224 && gateway.To4()[0] <= 239 {
		return errors.New("gateway 不能为组播地址")
	}
	priv := false
	b := gateway.To4()
	switch {
	case b[0] == 10:
		priv = true
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
		priv = true
	case b[0] == 192 && b[1] == 168:
		priv = true
	}
	if !priv {
		return errors.New("gateway 不能为公网地址")
	}
	netmask := net.ParseIP(netmaskStr)
	if netmask == nil || netmask.To4() == nil {
		return errors.New("netmask 必须为合法 IPv4 地址")
	}
	mask := netmask.To4()
	val := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	if val == 0 || val == 0xFFFFFFFF {
		return errors.New("netmask 不能为全0或全255")
	}
	foundZero := false
	for i := 31; i >= 0; i-- {
		if (val & (1 << uint(i))) == 0 {
			foundZero = true
		} else if foundZero {
			return errors.New("netmask 必须为连续的1后跟连续的0")
		}
	}
	return nil
}

func validateDNSServers(servers []string) error {
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			return errors.New("dns_servers 不能为空字符串")
		}
		ip := net.ParseIP(server)
		if ip == nil || ip.To4() == nil {
			return errors.New("dns_servers 必须为合法 IPv4 地址列表")
		}
	}
	return nil
}

func validateDNSMatchDomains(domains []string, domainRe *regexp.Regexp) error {
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return errors.New("dns_match_domains 不能为空字符串")
		}
		if !domainRe.MatchString(domain) {
			return errors.New("dns_match_domains 必须为合法域名列表")
		}
	}
	return nil
}

func validateServiceIP(serviceIP string, gateway net.IP, netmaskStr string, field string) error {
	serviceIP = strings.TrimSpace(serviceIP)
	if serviceIP == "" {
		return nil
	}
	ip := net.ParseIP(serviceIP)
	if ip == nil || ip.To4() == nil {
		return errors.New(field + " 必须为合法 IPv4 地址")
	}
	if gateway == nil || gateway.To4() == nil || strings.TrimSpace(netmaskStr) == "" {
		return errors.New(field + " 需要对应合法的 gateway 和 netmask")
	}
	maskIP := net.ParseIP(netmaskStr)
	if maskIP == nil || maskIP.To4() == nil {
		return errors.New(field + " 对应的 netmask 必须为合法 IPv4 地址")
	}
	mask := net.IPMask(maskIP.To4())
	requested := ip.To4()
	gateway4 := gateway.To4()
	if requested.Equal(gateway4) {
		return errors.New(field + " 不能与 gateway 相同")
	}
	networkIP := ipv4ToUint32(gateway4) & ipv4ToUint32(net.IP(mask))
	maskUint := ipv4ToUint32(net.IP(mask))
	serviceUint := ipv4ToUint32(requested)
	broadcast := networkIP | ^maskUint
	first := networkIP + 1
	last := broadcast - 1
	if serviceUint < first || serviceUint > last {
		return errors.New(field + " 必须落在对应网段可用地址范围内")
	}
	return nil
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
