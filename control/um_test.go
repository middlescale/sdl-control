package control

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUserManagementCreateBindLookup(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("alice")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	enr, err := um.CreateEnrollment(user.UserID, time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment failed: %v", err)
	}
	pub := []byte("device-pubkey-a")
	dev, err := um.BindDeviceByEnrollment(enr.Code, "device-a", pub, "ed25519")
	if err != nil {
		t.Fatalf("BindDeviceByEnrollment failed: %v", err)
	}
	if dev.UserID != user.UserID {
		t.Fatalf("unexpected user id: %s", dev.UserID)
	}
	lookup, ok := um.FindUserByDevicePubKey(pub, "ed25519")
	if !ok {
		t.Fatalf("FindUserByDevicePubKey not found")
	}
	if lookup.UserID != user.UserID {
		t.Fatalf("unexpected lookup user id: %s", lookup.UserID)
	}
}

func TestUserManagementEnrollmentSingleUse(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("bob")
	enr, _ := um.CreateEnrollment(user.UserID, time.Minute)
	_, err := um.BindDeviceByEnrollment(enr.Code, "device-b", []byte("pk-b"), "ed25519")
	if err != nil {
		t.Fatalf("first bind failed: %v", err)
	}
	_, err = um.BindDeviceByEnrollment(enr.Code, "device-c", []byte("pk-c"), "ed25519")
	if err == nil {
		t.Fatalf("expected second bind to fail for used enrollment")
	}
}

func TestUserManagementRejectCrossUserDeviceKeyReuse(t *testing.T) {
	um := NewUserManager()
	u1, _ := um.CreateUser("u1")
	u2, _ := um.CreateUser("u2")
	e1, _ := um.CreateEnrollment(u1.UserID, time.Minute)
	e2, _ := um.CreateEnrollment(u2.UserID, time.Minute)
	pub := []byte("same-device-key")
	if _, err := um.BindDeviceByEnrollment(e1.Code, "device-1", pub, "ed25519"); err != nil {
		t.Fatalf("bind user1 failed: %v", err)
	}
	if _, err := um.BindDeviceByEnrollment(e2.Code, "device-2", pub, "ed25519"); err == nil {
		t.Fatalf("expected cross-user key reuse to fail")
	}
}

func TestUserManagementBasicPolicyGeneratedOnCreateUser(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("policy-user")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	policy, ok := um.GetPolicy(user.UserID)
	if !ok {
		t.Fatalf("expected default policy generated")
	}
	if !policy.AllowP2P || !policy.AllowRelay {
		t.Fatalf("unexpected default policy flags: %+v", policy)
	}
	if policy.MaxDevices <= 0 {
		t.Fatalf("unexpected max devices: %d", policy.MaxDevices)
	}
	if policy.GroupName == "" {
		t.Fatalf("expected group name")
	}
	if policy.UserExpireAtUnixMs != 0 {
		t.Fatalf("expected default non-expiring user")
	}
	if policy.UserGracePeriodSeconds <= 0 {
		t.Fatalf("expected positive grace period")
	}
}

func TestUserManagementRegenerateBasicPolicy(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("policy-user-2")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	p1, ok := um.GetPolicy(user.UserID)
	if !ok {
		t.Fatalf("policy not found")
	}
	time.Sleep(time.Millisecond)
	p2, err := um.GenerateBasicPolicy(user.UserID)
	if err != nil {
		t.Fatalf("GenerateBasicPolicy failed: %v", err)
	}
	if p2.UpdatedAt.Before(p1.UpdatedAt) {
		t.Fatalf("expected updated_at move forward")
	}
}

func TestIssueAndAuthDeviceTicket(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("ticket-user")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	tk, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket failed: %v", err)
	}
	if tk.GroupName != "g1.ms.net" {
		t.Fatalf("expected normalized group name, got %s", tk.GroupName)
	}
	if _, err = um.AuthDevice(user.UserID, "g1.ms.net", "dev-1", tk.Ticket, []byte("pk-dev-1")); err != nil {
		t.Fatalf("AuthDevice failed: %v", err)
	}
	if !um.IsAuthedDevice("g1.ms.net", "dev-1") {
		t.Fatalf("device should be authed")
	}
	if _, err = um.AuthDevice(user.UserID, "g1.ms.net", "dev-1", tk.Ticket, []byte("pk-dev-1")); err == nil {
		t.Fatalf("expected used ticket reject")
	}
}

func TestCreateUserWithIDIsIdempotent(t *testing.T) {
	um := NewUserManager()
	user1, err := um.CreateUserWithID("user-1", "ms.net", "g1.ms.net")
	if err != nil {
		t.Fatalf("CreateUserWithID first failed: %v", err)
	}
	user2, err := um.CreateUserWithID("user-1", "ms.net", "g1.ms.net")
	if err != nil {
		t.Fatalf("CreateUserWithID second failed: %v", err)
	}
	if user1.UserID != user2.UserID {
		t.Fatalf("expected same user id, got %s and %s", user1.UserID, user2.UserID)
	}
}

func TestListUsersFiltersByUserIDWildcardAndSorts(t *testing.T) {
	um := NewUserManager()
	for _, tc := range []struct {
		userID string
		group  string
	}{
		{userID: "sdl-charlie", group: "sales"},
		{userID: "admin-1", group: "default"},
		{userID: "sdl-alpha", group: "marketing"},
		{userID: "sdl-beta-2", group: "sales"},
	} {
		if _, err := um.CreateUserWithID(tc.userID, "ms.net", tc.group); err != nil {
			t.Fatalf("CreateUserWithID(%q) failed: %v", tc.userID, err)
		}
	}

	users := um.ListUsers("sdl-?lpha")
	if len(users) != 1 || users[0].UserID != "sdl-alpha" || users[0].Name != "sdl-alpha" || users[0].Group != "marketing.ms.net" {
		t.Fatalf("unexpected question-mark filter result: %+v", users)
	}

	users = um.ListUsers("sdl-*")
	got := make([]string, 0, len(users))
	for _, user := range users {
		got = append(got, user.UserID)
		if user.Domain != "ms.net" || user.CreatedAtUnix <= 0 {
			t.Fatalf("unexpected user metadata: %+v", user)
		}
	}
	want := []string{"sdl-alpha", "sdl-beta-2", "sdl-charlie"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected sorted users: got %v want %v", got, want)
	}

	if users := um.ListUsers("SDL-*"); len(users) != 0 {
		t.Fatalf("expected case-sensitive filter, got %+v", users)
	}
}

func TestUserNameMatchesContainsAndWildcardCaseInsensitive(t *testing.T) {
	for _, tc := range []struct {
		filter string
		name   string
		want   bool
	}{
		{filter: "huang", name: "patrick huang", want: true},
		{filter: "HUANG", name: "patrick huang", want: true},
		{filter: "pat*huang", name: "Patrick Huang", want: true},
		{filter: "patrick ?uang", name: "Patrick Huang", want: true},
		{filter: "alice", name: "Patrick Huang", want: false},
	} {
		if got := userNameMatches(tc.filter, tc.name); got != tc.want {
			t.Fatalf("userNameMatches(%q, %q) = %v, want %v", tc.filter, tc.name, got, tc.want)
		}
	}
}

func TestIssueDeviceTicketExpiry(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("ticket-user-expire")
	tk, err := um.IssueDeviceTicket(user.UserID, "g1", time.Millisecond)
	if err != nil {
		t.Fatalf("IssueDeviceTicket failed: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err = um.AuthDevice(user.UserID, "g1.ms.net", "dev-1", tk.Ticket, []byte("pk-dev-1")); err == nil {
		t.Fatalf("expected expired ticket reject")
	}
}

func TestIssueDeviceTicketFullDomainValidation(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("ticket-domain-user")
	if _, err := um.IssueDeviceTicket(user.UserID, "sales.dev.net", time.Minute); err == nil {
		t.Fatalf("expected mismatch domain reject")
	}
	if _, err := um.IssueDeviceTicket(user.UserID, "sales.ms.net", time.Minute); err != nil {
		t.Fatalf("expected matching fqdn to pass: %v", err)
	}
}

func TestIssueDeviceTicketUsesSecureRandomID(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("ticket-random-user")

	tk1, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket first failed: %v", err)
	}
	tk2, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket second failed: %v", err)
	}
	if tk1.Ticket == tk2.Ticket {
		t.Fatalf("expected unique ticket ids")
	}
	for _, tk := range []string{tk1.Ticket, tk2.Ticket} {
		if !strings.HasPrefix(tk, "dtk-") {
			t.Fatalf("expected dtk- prefix, got %s", tk)
		}
		if len(tk) != len("dtk-")+32 {
			t.Fatalf("expected 128-bit hex ticket id, got %s", tk)
		}
	}
}

func TestExtendAuthedDeviceExpirySingle(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("extend-single")
	tk, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket failed: %v", err)
	}
	record, err := um.AuthDevice(user.UserID, "g1.ms.net", "dev-1", tk.Ticket, []byte("pk-dev-1"))
	if err != nil {
		t.Fatalf("AuthDevice failed: %v", err)
	}
	updated, err := um.ExtendAuthedDeviceExpiry(user.UserID, "g1", "dev-1", 2*time.Hour, false)
	if err != nil {
		t.Fatalf("ExtendAuthedDeviceExpiry failed: %v", err)
	}
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated device, got %d", len(updated))
	}
	if !updated[0].AuthExpireAt.After(record.AuthExpireAt) {
		t.Fatalf("expected auth expiry to move forward: before=%v after=%v", record.AuthExpireAt, updated[0].AuthExpireAt)
	}
}

func TestExtendAuthedDeviceExpiryAll(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("extend-all")
	tk1, _ := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	tk2, _ := um.IssueDeviceTicket(user.UserID, "g2", time.Minute)
	record1, err := um.AuthDevice(user.UserID, "g1.ms.net", "dev-1", tk1.Ticket, []byte("pk-dev-1"))
	if err != nil {
		t.Fatalf("AuthDevice dev-1 failed: %v", err)
	}
	record2, err := um.AuthDevice(user.UserID, "g2.ms.net", "dev-2", tk2.Ticket, []byte("pk-dev-2"))
	if err != nil {
		t.Fatalf("AuthDevice dev-2 failed: %v", err)
	}
	updated, err := um.ExtendAuthedDeviceExpiry(user.UserID, "", "", 24*time.Hour, true)
	if err != nil {
		t.Fatalf("ExtendAuthedDeviceExpiry all failed: %v", err)
	}
	if len(updated) != 2 {
		t.Fatalf("expected 2 updated devices, got %d", len(updated))
	}
	records := um.ListAuthedDevicesByUser(user.UserID)
	if len(records) != 2 {
		t.Fatalf("expected 2 listed devices, got %d", len(records))
	}
	for _, record := range records {
		switch record.DeviceID {
		case "dev-1":
			if !record.AuthExpireAt.After(record1.AuthExpireAt) {
				t.Fatalf("dev-1 expiry not extended")
			}
		case "dev-2":
			if !record.AuthExpireAt.After(record2.AuthExpireAt) {
				t.Fatalf("dev-2 expiry not extended")
			}
		default:
			t.Fatalf("unexpected device %s", record.DeviceID)
		}
	}
}

func TestAssignAuthedDeviceDisplayNameAddsSuffixOnConflict(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUserWithID("sdl-user", "ms.net", "user")
	tk1, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	tk2, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	if _, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-1", tk1.Ticket, []byte("pk-dev-1")); err != nil {
		t.Fatalf("AuthDevice dev-1 failed: %v", err)
	}
	if _, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-2", tk2.Ticket, []byte("pk-dev-2")); err != nil {
		t.Fatalf("AuthDevice dev-2 failed: %v", err)
	}
	record1, err := um.AssignAuthedDeviceDisplayName("user.ms.net", "dev-1", "aliyun-jp")
	if err != nil {
		t.Fatalf("AssignAuthedDeviceDisplayName dev-1 failed: %v", err)
	}
	record2, err := um.AssignAuthedDeviceDisplayName("user.ms.net", "dev-2", "aliyun-jp")
	if err != nil {
		t.Fatalf("AssignAuthedDeviceDisplayName dev-2 failed: %v", err)
	}
	if record1.DisplayName != "aliyun-jp" || record2.DisplayName != "aliyun-jp-1" {
		t.Fatalf("unexpected assigned names: %q %q", record1.DisplayName, record2.DisplayName)
	}
}

func TestRenameAuthedDeviceRejectsConflictAndDeleteFreesName(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUserWithID("sdl-user", "ms.net", "user")
	tk1, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	tk2, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	if _, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-1", tk1.Ticket, []byte("pk-dev-1")); err != nil {
		t.Fatalf("AuthDevice dev-1 failed: %v", err)
	}
	if _, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-2", tk2.Ticket, []byte("pk-dev-2")); err != nil {
		t.Fatalf("AuthDevice dev-2 failed: %v", err)
	}
	if _, err := um.RenameAuthedDevice(user.UserID, "user", "dev-1", "aliyun-jp"); err != nil {
		t.Fatalf("RenameAuthedDevice dev-1 failed: %v", err)
	}
	if _, err := um.RenameAuthedDevice(user.UserID, "user", "dev-2", "ALIYUN-JP"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate rename error, got %v", err)
	}
	deleted, err := um.DeleteAuthedDevice(user.UserID, "user", "dev-1")
	if err != nil {
		t.Fatalf("DeleteAuthedDevice failed: %v", err)
	}
	if len(deleted) != 1 || deleted[0].DeviceID != "dev-1" {
		t.Fatalf("unexpected deleted devices: %+v", deleted)
	}
	renamed, err := um.RenameAuthedDevice(user.UserID, "user", "dev-2", "aliyun-jp")
	if err != nil {
		t.Fatalf("RenameAuthedDevice after delete failed: %v", err)
	}
	if renamed.DisplayName != "aliyun-jp" {
		t.Fatalf("unexpected renamed display name: %+v", renamed)
	}
}

func TestAuthDevicePreservesExistingDisplayName(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUserWithID("sdl-user", "ms.net", "user")
	tk1, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	if _, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-1", tk1.Ticket, []byte("pk-dev-1")); err != nil {
		t.Fatalf("AuthDevice initial failed: %v", err)
	}
	if _, err := um.RenameAuthedDevice(user.UserID, "user", "dev-1", "aliyun-jp"); err != nil {
		t.Fatalf("RenameAuthedDevice failed: %v", err)
	}
	tk2, _ := um.IssueDeviceTicket(user.UserID, "user", time.Minute)
	record, err := um.AuthDevice(user.UserID, "user.ms.net", "dev-1", tk2.Ticket, []byte("pk-dev-1"))
	if err != nil {
		t.Fatalf("AuthDevice reauth failed: %v", err)
	}
	if record.DisplayName != "aliyun-jp" {
		t.Fatalf("reauth lost display name: %+v", record)
	}
}
