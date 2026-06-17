package control

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type UMUser struct {
	UserID    string
	Name      string
	Domain    string
	CreatedAt time.Time
}

type UMUserAdminView struct {
	UserID        string `json:"user_id"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	Group         string `json:"group"`
	Domain        string `json:"domain"`
	CreatedAtUnix int64  `json:"created_at_unix,omitempty"`
}

type UMEnrollment struct {
	Code      string
	UserID    string
	ExpireAt  time.Time
	Used      bool
	CreatedAt time.Time
}

type UMDevice struct {
	UserID      string
	DeviceID    string
	DisplayName string
	PubKeyAlg   string
	PubKeyHex   string
	CreatedAt   time.Time
	LastBoundAt time.Time
}

type UMPolicy struct {
	UserID                  string
	GroupName               string
	UserExpireAtUnixMs      int64
	UserGracePeriodSeconds  int64
	AllowP2P                bool
	AllowRelay              bool
	MaxDevices              int
	EnrollmentTTLSeconds    int64
	GatewayTicketTTLSeconds int64
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type UMDeviceTicket struct {
	Ticket    string
	UserID    string
	GroupName string
	ExpireAt  time.Time
	Used      bool
	CreatedAt time.Time
}

type UMAuthDevice struct {
	UserID       string
	GroupName    string
	DeviceID     string
	DisplayName  string
	PubKeyHex    string
	AuthedAt     time.Time
	AuthExpireAt time.Time
}

type UserManager struct {
	mu             sync.RWMutex
	store          UMStore
	userSeq        atomic.Uint64
	enrollmentSeq  atomic.Uint64
	users          map[string]UMUser
	policies       map[string]UMPolicy
	enrollments    map[string]UMEnrollment
	deviceByPubKey map[string]UMDevice
	authedDevices  map[string]UMAuthDevice
	deviceTickets  map[string]UMDeviceTicket
}

const defaultDeviceAuthTTL = 30 * 24 * time.Hour

func NewUserManager() *UserManager {
	m := &UserManager{
		users:          make(map[string]UMUser),
		policies:       make(map[string]UMPolicy),
		enrollments:    make(map[string]UMEnrollment),
		deviceByPubKey: make(map[string]UMDevice),
		authedDevices:  make(map[string]UMAuthDevice),
		deviceTickets:  make(map[string]UMDeviceTicket),
	}
	return m
}

func NewUserManagerWithStore(store UMStore) (*UserManager, error) {
	m := NewUserManager()
	m.store = store
	snapshot, err := store.Load()
	if err != nil {
		return nil, err
	}
	m.restore(snapshot)
	return m, nil
}

func (m *UserManager) CreateUser(name string, domain ...string) (UMUser, error) {
	if name == "" {
		return UMUser{}, fmt.Errorf("user name is empty")
	}
	userDomain := "ms.net"
	if len(domain) > 0 && strings.TrimSpace(domain[0]) != "" {
		userDomain = strings.TrimSpace(domain[0])
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := ""
	for {
		candidate := fmt.Sprintf("u-%d", m.userSeq.Add(1))
		if _, exists := m.users[candidate]; !exists {
			id = candidate
			break
		}
	}
	user := UMUser{
		UserID:    id,
		Name:      name,
		Domain:    userDomain,
		CreatedAt: time.Now(),
	}
	m.users[id] = user
	m.policies[id] = m.generateBasicPolicyLocked(id)
	err := m.saveLocked()
	if err != nil {
		return UMUser{}, err
	}
	return user, nil
}

func (m *UserManager) CreateUserWithID(userID string, domain string, group string) (UMUser, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return UMUser{}, fmt.Errorf("user id is empty")
	}
	userDomain := "ms.net"
	if strings.TrimSpace(domain) != "" {
		userDomain = strings.TrimSpace(domain)
	}
	defaultGroup := strings.TrimSpace(group)
	if defaultGroup == "" {
		defaultGroup = "default"
	}
	normalizedGroup, err := normalizeGroupForUser(defaultGroup, userDomain)
	if err != nil {
		return UMUser{}, err
	}
	user := UMUser{
		UserID:    userID,
		Name:      userID,
		Domain:    userDomain,
		CreatedAt: time.Now(),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, exists := m.users[userID]; exists {
		if existing.Domain != userDomain {
			return UMUser{}, fmt.Errorf("user %s already exists", userID)
		}
		if _, ok := m.policies[userID]; !ok {
			policy := m.generateBasicPolicyLocked(userID)
			policy.GroupName = normalizedGroup
			policy.UpdatedAt = time.Now()
			m.policies[userID] = policy
			if err := m.saveLocked(); err != nil {
				return UMUser{}, err
			}
		}
		return existing, nil
	}
	m.users[userID] = user
	policy := m.generateBasicPolicyLocked(userID)
	policy.GroupName = normalizedGroup
	policy.UpdatedAt = time.Now()
	m.policies[userID] = policy
	err = m.saveLocked()
	if err != nil {
		return UMUser{}, err
	}
	return user, nil
}

func (m *UserManager) ListUsers(idFilter string) []UMUserAdminView {
	idFilter = strings.TrimSpace(idFilter)
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]UMUserAdminView, 0, len(m.users))
	for _, user := range m.users {
		if idFilter != "" && !wildcardMatch(idFilter, user.UserID) {
			continue
		}
		group := ""
		if policy, ok := m.policies[user.UserID]; ok {
			group = policy.GroupName
		}
		users = append(users, UMUserAdminView{
			UserID:        user.UserID,
			Name:          user.Name,
			Group:         group,
			Domain:        user.Domain,
			CreatedAtUnix: user.CreatedAt.Unix(),
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].UserID < users[j].UserID
	})
	return users
}

func wildcardMatch(pattern, value string) bool {
	patternRunes := []rune(pattern)
	valueRunes := []rune(value)
	matches := make([]bool, len(valueRunes)+1)
	matches[0] = true
	for _, patternRune := range patternRunes {
		next := make([]bool, len(valueRunes)+1)
		if patternRune == '*' {
			next[0] = matches[0]
			for i := 1; i <= len(valueRunes); i++ {
				next[i] = matches[i] || next[i-1]
			}
		} else {
			for i := 1; i <= len(valueRunes); i++ {
				next[i] = matches[i-1] && (patternRune == '?' || patternRune == valueRunes[i-1])
			}
		}
		matches = next
	}
	return matches[len(valueRunes)]
}

func userNameMatches(nameFilter, name string) bool {
	nameFilter = strings.ToLower(strings.TrimSpace(nameFilter))
	name = strings.ToLower(strings.TrimSpace(name))
	if nameFilter == "" {
		return true
	}
	if strings.ContainsAny(nameFilter, "*?") {
		return wildcardMatch(nameFilter, name)
	}
	return strings.Contains(name, nameFilter)
}

func (m *UserManager) CreateEnrollment(userID string, ttl time.Duration) (UMEnrollment, error) {
	if ttl <= 0 {
		return UMEnrollment{}, fmt.Errorf("invalid ttl")
	}
	m.mu.RLock()
	_, exists := m.users[userID]
	m.mu.RUnlock()
	if !exists {
		return UMEnrollment{}, fmt.Errorf("user not found")
	}
	seq := m.enrollmentSeq.Add(1)
	code := fmt.Sprintf("enr-%d-%d", time.Now().UnixNano(), seq)
	enrollment := UMEnrollment{
		Code:      code,
		UserID:    userID,
		ExpireAt:  time.Now().Add(ttl),
		Used:      false,
		CreatedAt: time.Now(),
	}
	m.mu.Lock()
	m.enrollments[code] = enrollment
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return UMEnrollment{}, err
	}
	return enrollment, nil
}

func (m *UserManager) BindDeviceByEnrollment(code string, deviceID string, pubKey []byte, pubKeyAlg string) (UMDevice, error) {
	if code == "" {
		return UMDevice{}, fmt.Errorf("enrollment code is empty")
	}
	if deviceID == "" {
		return UMDevice{}, fmt.Errorf("device_id is empty")
	}
	if len(pubKey) == 0 {
		return UMDevice{}, fmt.Errorf("device public key is empty")
	}
	if pubKeyAlg == "" {
		return UMDevice{}, fmt.Errorf("device public key algorithm is empty")
	}
	now := time.Now()
	pubKeyHex := toPubKeyHex(pubKey, pubKeyAlg)

	m.mu.Lock()
	defer m.mu.Unlock()
	enrollment, ok := m.enrollments[code]
	if !ok {
		return UMDevice{}, fmt.Errorf("enrollment not found")
	}
	if enrollment.Used {
		return UMDevice{}, fmt.Errorf("enrollment already used")
	}
	if now.After(enrollment.ExpireAt) {
		return UMDevice{}, fmt.Errorf("enrollment expired")
	}
	if _, exists := m.users[enrollment.UserID]; !exists {
		return UMDevice{}, fmt.Errorf("user not found")
	}
	if existing, ok := m.deviceByPubKey[pubKeyHex]; ok && existing.UserID != enrollment.UserID {
		return UMDevice{}, fmt.Errorf("device key already bound to another user")
	}
	device := UMDevice{
		UserID:      enrollment.UserID,
		DeviceID:    deviceID,
		PubKeyAlg:   pubKeyAlg,
		PubKeyHex:   pubKeyHex,
		CreatedAt:   now,
		LastBoundAt: now,
	}
	m.deviceByPubKey[pubKeyHex] = device
	enrollment.Used = true
	m.enrollments[code] = enrollment
	if err := m.saveLocked(); err != nil {
		return UMDevice{}, err
	}
	return device, nil
}

func (m *UserManager) FindUserByDevicePubKey(pubKey []byte, pubKeyAlg string) (UMUser, bool) {
	pubKeyHex := toPubKeyHex(pubKey, pubKeyAlg)
	m.mu.RLock()
	defer m.mu.RUnlock()
	device, ok := m.deviceByPubKey[pubKeyHex]
	if !ok {
		return UMUser{}, false
	}
	user, ok := m.users[device.UserID]
	return user, ok
}

func (m *UserManager) GetPolicy(userID string) (UMPolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.policies[userID]
	return policy, ok
}

func (m *UserManager) GenerateBasicPolicy(userID string) (UMPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return UMPolicy{}, fmt.Errorf("user not found")
	}
	policy := m.generateBasicPolicyLocked(userID)
	if existing, ok := m.policies[userID]; ok {
		policy.CreatedAt = existing.CreatedAt
	}
	m.policies[userID] = policy
	if err := m.saveLocked(); err != nil {
		return UMPolicy{}, err
	}
	return policy, nil
}

func (m *UserManager) IssueDeviceTicket(userID string, groupName string, ttl time.Duration) (UMDeviceTicket, error) {
	if userID == "" {
		return UMDeviceTicket{}, fmt.Errorf("user id is empty")
	}
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return UMDeviceTicket{}, fmt.Errorf("group name is empty")
	}
	if ttl <= 0 {
		return UMDeviceTicket{}, fmt.Errorf("invalid ttl")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[userID]
	if !ok {
		return UMDeviceTicket{}, fmt.Errorf("user not found")
	}
	fullGroupName, err := normalizeGroupForUser(groupName, user.Domain)
	if err != nil {
		return UMDeviceTicket{}, err
	}
	ticketID, err := newSecureTicketID()
	if err != nil {
		return UMDeviceTicket{}, err
	}
	ticket := UMDeviceTicket{
		Ticket:    ticketID,
		UserID:    userID,
		GroupName: fullGroupName,
		ExpireAt:  time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}
	m.deviceTickets[ticket.Ticket] = ticket
	if err := m.saveLocked(); err != nil {
		return UMDeviceTicket{}, err
	}
	return ticket, nil
}

func newSecureTicketID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate secure ticket id: %w", err)
	}
	return "dtk-" + hex.EncodeToString(buf[:]), nil
}

func normalizeGroupForUser(groupName string, userDomain string) (string, error) {
	if strings.TrimSpace(userDomain) == "" {
		userDomain = "ms.net"
	}
	if strings.Contains(groupName, ".") {
		if groupName == userDomain {
			return groupName, nil
		}
		if !strings.HasSuffix(groupName, "."+userDomain) {
			return "", fmt.Errorf("group %s does not belong to user domain %s", groupName, userDomain)
		}
		return groupName, nil
	}
	return groupName + "." + userDomain, nil
}

func (m *UserManager) ValidateDeviceAuth(userID string, groupName string, deviceID string, ticket string) (string, error) {
	if userID == "" || groupName == "" || deviceID == "" || ticket == "" {
		return "", fmt.Errorf("user/group/device/ticket required")
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.deviceTickets[ticket]
	if !ok {
		return "", fmt.Errorf("ticket not found")
	}
	if t.Used {
		return "", fmt.Errorf("ticket already used")
	}
	if now.After(t.ExpireAt) {
		return "", fmt.Errorf("ticket expired")
	}
	user, ok := m.users[userID]
	if !ok {
		return "", fmt.Errorf("user not found")
	}
	normalizedGroup, err := normalizeGroupForUser(groupName, user.Domain)
	if err != nil {
		return "", err
	}
	if t.UserID != userID || t.GroupName != normalizedGroup {
		return "", fmt.Errorf("ticket mismatch")
	}
	return normalizedGroup, nil
}

func (m *UserManager) AuthDevice(
	userID string,
	groupName string,
	deviceID string,
	ticket string,
	pubKey []byte,
) (UMAuthDevice, error) {
	if len(pubKey) == 0 {
		return UMAuthDevice{}, fmt.Errorf("device public key is empty")
	}
	normalizedGroup, err := m.ValidateDeviceAuth(userID, groupName, deviceID, ticket)
	if err != nil {
		return UMAuthDevice{}, err
	}
	now := time.Now()
	pubKeyHex := toPubKeyHex(pubKey, "ed25519")
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.deviceTickets[ticket]
	record := UMAuthDevice{
		UserID:       userID,
		GroupName:    normalizedGroup,
		DeviceID:     deviceID,
		DisplayName:  "",
		PubKeyHex:    pubKeyHex,
		AuthedAt:     now,
		AuthExpireAt: now.Add(defaultDeviceAuthTTL),
	}
	m.authedDevices[authedDeviceKey(normalizedGroup, deviceID)] = record
	t.Used = true
	m.deviceTickets[ticket] = t
	if err := m.saveLocked(); err != nil {
		return UMAuthDevice{}, err
	}
	return record, nil
}

func (m *UserManager) IsAuthedDevice(groupName string, deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.authedDevices[authedDeviceKey(groupName, deviceID)]
	return ok
}

func (m *UserManager) GetAuthedDevice(groupName string, deviceID string) (UMAuthDevice, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.authedDevices[authedDeviceKey(groupName, deviceID)]
	return record, ok
}

func (m *UserManager) ListAuthedDevicesByUser(userID string) []UMAuthDevice {
	m.mu.RLock()
	defer m.mu.RUnlock()

	devices := make([]UMAuthDevice, 0)
	for _, record := range m.authedDevices {
		if record.UserID == userID {
			devices = append(devices, record)
		}
	}
	return devices
}

func (m *UserManager) ExtendAuthedDeviceExpiry(
	userID string,
	groupName string,
	deviceID string,
	ttl time.Duration,
	all bool,
) ([]UMAuthDevice, error) {
	userID = strings.TrimSpace(userID)
	groupName = strings.TrimSpace(groupName)
	deviceID = strings.TrimSpace(deviceID)
	if userID == "" {
		return nil, fmt.Errorf("user id is empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("invalid ttl")
	}
	if !all && deviceID == "" {
		return nil, fmt.Errorf("device id is required unless --all is set")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	if groupName != "" {
		normalized, err := normalizeGroupForUser(groupName, user.Domain)
		if err != nil {
			return nil, err
		}
		groupName = normalized
	}

	matches := make([]string, 0)
	for key, record := range m.authedDevices {
		if record.UserID != userID {
			continue
		}
		if groupName != "" && record.GroupName != groupName {
			continue
		}
		if deviceID != "" && record.DeviceID != deviceID {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("authed device not found")
	}
	if !all && deviceID != "" && groupName == "" && len(matches) > 1 {
		return nil, fmt.Errorf("device id %s matched multiple groups; specify --group", deviceID)
	}

	now := time.Now()
	updated := make([]UMAuthDevice, 0, len(matches))
	for _, key := range matches {
		record := m.authedDevices[key]
		base := record.AuthExpireAt
		if base.IsZero() || base.Before(now) {
			base = now
		}
		record.AuthExpireAt = base.Add(ttl)
		m.authedDevices[key] = record
		updated = append(updated, record)
	}
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return updated, nil
}

func (m *UserManager) CheckAuthedDevice(groupName string, deviceID string, pubKey []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.authedDevices[authedDeviceKey(groupName, deviceID)]
	if !ok {
		return fmt.Errorf("not_auth")
	}
	if !record.AuthExpireAt.IsZero() && time.Now().After(record.AuthExpireAt) {
		return fmt.Errorf("auth_expired")
	}
	if len(pubKey) == 0 {
		return fmt.Errorf("device_key_mismatch")
	}
	if record.PubKeyHex != toPubKeyHex(pubKey, "ed25519") {
		return fmt.Errorf("device_key_mismatch")
	}
	return nil
}

func (m *UserManager) SetAuthedDeviceDisplayName(
	groupName string,
	deviceID string,
	displayName string,
) error {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return fmt.Errorf("display name is empty")
	}
	if len(displayName) > 128 {
		return fmt.Errorf("display name too long")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := authedDeviceKey(groupName, deviceID)
	record, ok := m.authedDevices[key]
	if !ok {
		return fmt.Errorf("authed device not found")
	}
	networkKey := NewNetworkIdentity(record.GroupName, record.UserID).Key()
	for _, existing := range m.authedDevices {
		if existing.DeviceID == deviceID {
			continue
		}
		if NewNetworkIdentity(existing.GroupName, existing.UserID).Key() != networkKey {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existing.DisplayName), displayName) {
			return fmt.Errorf("display name already exists")
		}
	}
	record.DisplayName = displayName
	m.authedDevices[key] = record
	if err := m.saveLocked(); err != nil {
		return err
	}
	return nil
}

func (m *UserManager) RequireTicketAuthForGroup(groupName string) bool {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.deviceTickets {
		if t.GroupName == groupName && !t.Used && now.Before(t.ExpireAt) {
			return true
		}
	}
	return false
}

func toPubKeyHex(pubKey []byte, pubKeyAlg string) string {
	sum := sha256.Sum256(append([]byte(pubKeyAlg+":"), pubKey...))
	return hex.EncodeToString(sum[:])
}

func (m *UserManager) saveLocked() error {
	if m.store == nil {
		return nil
	}
	return m.store.Save(m.snapshotLocked())
}

func (m *UserManager) snapshotLocked() UMSnapshot {
	return UMSnapshot{
		UserSeq:          m.userSeq.Load(),
		EnrollmentSeq:    m.enrollmentSeq.Load(),
		Users:            cloneUsers(m.users),
		Policies:         clonePolicies(m.policies),
		Enrollments:      cloneEnrollments(m.enrollments),
		DeviceByPubKey:   cloneDevices(m.deviceByPubKey),
		CertifiedDevices: cloneAuthedDevices(m.authedDevices),
		DeviceTickets:    cloneDeviceTickets(m.deviceTickets),
	}
}

func (m *UserManager) restore(snapshot UMSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userSeq.Store(snapshot.UserSeq)
	m.enrollmentSeq.Store(snapshot.EnrollmentSeq)
	m.users = cloneUsers(snapshot.Users)
	m.policies = clonePolicies(snapshot.Policies)
	for userID := range m.users {
		if _, ok := m.policies[userID]; !ok {
			m.policies[userID] = m.generateBasicPolicyLocked(userID)
		}
	}
	m.enrollments = cloneEnrollments(snapshot.Enrollments)
	m.deviceByPubKey = cloneDevices(snapshot.DeviceByPubKey)
	m.authedDevices = cloneAuthedDevices(snapshot.CertifiedDevices)
	m.deviceTickets = cloneDeviceTickets(snapshot.DeviceTickets)
}

func cloneUsers(src map[string]UMUser) map[string]UMUser {
	dst := make(map[string]UMUser, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneEnrollments(src map[string]UMEnrollment) map[string]UMEnrollment {
	dst := make(map[string]UMEnrollment, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneDevices(src map[string]UMDevice) map[string]UMDevice {
	dst := make(map[string]UMDevice, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func clonePolicies(src map[string]UMPolicy) map[string]UMPolicy {
	dst := make(map[string]UMPolicy, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneAuthedDevices(src map[string]UMAuthDevice) map[string]UMAuthDevice {
	dst := make(map[string]UMAuthDevice, len(src))
	for k, v := range src {
		key := k
		if strings.TrimSpace(v.DeviceID) != "" {
			key = authedDeviceKey(strings.TrimSpace(v.GroupName), strings.TrimSpace(v.DeviceID))
		}
		dst[key] = v
	}
	return dst
}

func cloneDeviceTickets(src map[string]UMDeviceTicket) map[string]UMDeviceTicket {
	dst := make(map[string]UMDeviceTicket, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func authedDeviceKey(groupName string, deviceID string) string {
	return groupName + "|" + deviceID
}

func (m *UserManager) generateBasicPolicyLocked(userID string) UMPolicy {
	now := time.Now()
	return UMPolicy{
		UserID:                  userID,
		GroupName:               userID,
		UserExpireAtUnixMs:      0,
		UserGracePeriodSeconds:  int64((24 * time.Hour).Seconds()),
		AllowP2P:                true,
		AllowRelay:              true,
		MaxDevices:              32,
		EnrollmentTTLSeconds:    int64((15 * time.Minute).Seconds()),
		GatewayTicketTTLSeconds: int64((2 * time.Minute).Seconds()),
		CreatedAt:               now,
		UpdatedAt:               now,
	}
}
