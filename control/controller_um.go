package control

import (
	"fmt"
	"strings"
	"time"
)

func (c *Controller) UMCreateUser(name string, domain ...string) (UMUser, error) {
	selectedDomain := ""
	if len(domain) > 0 {
		selectedDomain = strings.TrimSpace(domain[0])
	}
	if selectedDomain == "" {
		selectedDomain = strings.TrimSpace(c.cfg.EffectiveDefaultDomain())
	}
	if selectedDomain == "" {
		selectedDomain = "ms.net"
	}
	if len(c.cfg.Domains) > 0 {
		if _, ok := c.cfg.Domains[selectedDomain]; !ok {
			return UMUser{}, fmt.Errorf("domain %s not configured", selectedDomain)
		}
	}
	return c.um.CreateUser(name, selectedDomain)
}

func (c *Controller) UMCreateUserWithID(userID string, group string, domain ...string) (UMUser, error) {
	selectedDomain := ""
	if len(domain) > 0 {
		selectedDomain = strings.TrimSpace(domain[0])
	}
	if selectedDomain == "" {
		trimmedGroup := strings.TrimSpace(group)
		if len(c.cfg.Domains) > 0 {
			if domainName, _, ok := matchDomainAndGroup(trimmedGroup, c.cfg.Domains); ok {
				selectedDomain = domainName
			}
		} else if idx := strings.Index(trimmedGroup, "."); idx > 0 && idx+1 < len(trimmedGroup) {
			selectedDomain = strings.TrimSpace(trimmedGroup[idx+1:])
		}
	}
	if selectedDomain == "" {
		selectedDomain = strings.TrimSpace(c.cfg.EffectiveDefaultDomain())
	}
	if selectedDomain == "" {
		selectedDomain = "ms.net"
	}
	if len(c.cfg.Domains) > 0 {
		if _, ok := c.cfg.Domains[selectedDomain]; !ok {
			return UMUser{}, fmt.Errorf("domain %s not configured", selectedDomain)
		}
	}
	return c.um.CreateUserWithID(userID, selectedDomain, group)
}

func (c *Controller) UMListUsers(filter string) []UMUserAdminView {
	return c.um.ListUsers(filter)
}

func (c *Controller) UMCreateEnrollment(userID string, ttl time.Duration) (UMEnrollment, error) {
	return c.um.CreateEnrollment(userID, ttl)
}

func (c *Controller) UMBindDevice(code string, deviceID string, pubKey []byte, pubKeyAlg string) (UMDevice, error) {
	return c.um.BindDeviceByEnrollment(code, deviceID, pubKey, pubKeyAlg)
}

func (c *Controller) UMFindUserByDevicePubKey(pubKey []byte, pubKeyAlg string) (UMUser, bool) {
	return c.um.FindUserByDevicePubKey(pubKey, pubKeyAlg)
}

func (c *Controller) UMGetPolicy(userID string) (UMPolicy, bool) {
	return c.um.GetPolicy(userID)
}

func (c *Controller) UMGenerateBasicPolicy(userID string) (UMPolicy, error) {
	return c.um.GenerateBasicPolicy(userID)
}

func (c *Controller) UMIssueDeviceTicket(userID string, groupName string, ttl time.Duration) (UMDeviceTicket, error) {
	return c.um.IssueDeviceTicket(userID, groupName, ttl)
}

func (c *Controller) UMValidateDeviceAuth(userID string, groupName string, deviceID string, ticket string) (string, error) {
	return c.um.ValidateDeviceAuth(userID, groupName, deviceID, ticket)
}

func (c *Controller) UMAuthDevice(userID string, groupName string, deviceID string, ticket string, pubKey []byte) (UMAuthDevice, error) {
	return c.um.AuthDevice(userID, groupName, deviceID, ticket, pubKey)
}

func (c *Controller) UMIsAuthedDevice(groupName string, deviceID string) bool {
	return c.um.IsAuthedDevice(groupName, deviceID)
}

func (c *Controller) UMGetAuthedDevice(groupName string, deviceID string) (UMAuthDevice, bool) {
	return c.um.GetAuthedDevice(groupName, deviceID)
}

func (c *Controller) UMCheckAuthedDevice(groupName string, deviceID string, pubKey []byte) error {
	return c.um.CheckAuthedDevice(groupName, deviceID, pubKey)
}

func (c *Controller) UMSetAuthedDeviceDisplayName(groupName string, deviceID string, displayName string) error {
	return c.um.SetAuthedDeviceDisplayName(groupName, deviceID, displayName)
}

func (c *Controller) UMExtendAuthedDeviceExpiry(
	userID string,
	groupName string,
	deviceID string,
	ttl time.Duration,
	all bool,
) ([]UMAuthDevice, error) {
	return c.um.ExtendAuthedDeviceExpiry(userID, groupName, deviceID, ttl, all)
}

func (c *Controller) UMRequireTicketAuthForGroup(groupName string) bool {
	return c.um.RequireTicketAuthForGroup(groupName)
}
