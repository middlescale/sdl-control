package control

import (
	"fmt"
	"sdl-control/control/store"
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

func (c *Controller) UMListUsers(idFilter, nameFilter string) ([]UMUserAdminView, error) {
	users := c.um.ListUsers(idFilter)
	if c.pgStore != nil {
		profiles, err := c.pgStore.ListWebUserProfiles()
		if err != nil {
			return nil, err
		}
		profileByUserID := make(map[string]store.WebUserProfile, len(profiles))
		for _, profile := range profiles {
			profileByUserID[strings.TrimSpace(profile.SDLUserID)] = profile
		}
		for i := range users {
			profile, ok := profileByUserID[users[i].UserID]
			if !ok {
				continue
			}
			users[i].Email = strings.TrimSpace(profile.Email)
			if name := strings.TrimSpace(profile.DisplayName); name != "" {
				users[i].Name = name
			}
		}
	}
	if strings.TrimSpace(nameFilter) == "" {
		return users, nil
	}
	filtered := make([]UMUserAdminView, 0, len(users))
	for _, user := range users {
		if userNameMatches(nameFilter, user.Name) {
			filtered = append(filtered, user)
		}
	}
	return filtered, nil
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

func (c *Controller) UMAssignAuthedDeviceDisplayName(groupName string, deviceID string, displayName string) (UMAuthDevice, error) {
	return c.um.AssignAuthedDeviceDisplayName(groupName, deviceID, displayName)
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

func (c *Controller) UMRenameAuthedDevice(userID string, groupName string, deviceID string, displayName string) (UMAuthDevice, error) {
	return c.um.RenameAuthedDevice(userID, groupName, deviceID, displayName)
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

func (c *Controller) UMDeleteAuthedDevice(userID string, groupName string, deviceID string) ([]UMAuthDevice, error) {
	return c.um.DeleteAuthedDevice(userID, groupName, deviceID)
}

func (c *Controller) DeleteAuthedDevice(userID string, groupName string, deviceID string) ([]UMAuthDevice, error) {
	records, err := c.UMDeleteAuthedDevice(userID, groupName, deviceID)
	if err != nil {
		return nil, err
	}
	c.removeAuthedDeviceRuntimeState(records)
	return records, nil
}

func (c *Controller) RenameAuthedDevice(userID string, groupName string, deviceID string, displayName string) (UMAuthDevice, error) {
	record, err := c.UMRenameAuthedDevice(userID, groupName, deviceID, displayName)
	if err != nil {
		return UMAuthDevice{}, err
	}
	c.updateAuthedDeviceRuntimeName(record)
	return record, nil
}

func (c *Controller) UMRequireTicketAuthForGroup(groupName string) bool {
	return c.um.RequireTicketAuthForGroup(groupName)
}
