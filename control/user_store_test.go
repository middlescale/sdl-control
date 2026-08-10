package control

import (
	"path/filepath"
	"testing"
	"time"
)

func TestJSONUMStorePersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "um.json")
	um, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("NewUserManagerWithStore failed: %v", err)
	}
	user, err := um.CreateUser("alice")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	enrollment, err := um.CreateEnrollment(user.UserID, time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment failed: %v", err)
	}
	pub := []byte("pk-persist")
	if _, err := um.BindDeviceByEnrollment(enrollment.Code, "device-a", pub, "ed25519"); err != nil {
		t.Fatalf("BindDeviceByEnrollment failed: %v", err)
	}
	tk, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket failed: %v", err)
	}

	um2, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("reload NewUserManagerWithStore failed: %v", err)
	}
	gotUser, ok := um2.FindUserByDevicePubKey(pub, "ed25519")
	if !ok {
		t.Fatalf("FindUserByDevicePubKey after reload failed")
	}
	if gotUser.UserID != user.UserID {
		t.Fatalf("unexpected reloaded user id: %s", gotUser.UserID)
	}
	policy, ok := um2.GetPolicy(user.UserID)
	if !ok {
		t.Fatalf("expected policy after reload")
	}
	if !policy.AllowP2P || !policy.AllowRelay {
		t.Fatalf("unexpected default policy after reload: %+v", policy)
	}
	if policy.GroupName == "" || policy.UserGracePeriodSeconds <= 0 {
		t.Fatalf("expected group/expiry fields after reload: %+v", policy)
	}
	if !um2.RequireTicketAuthForGroup(tk.GroupName) {
		t.Fatalf("expected ticket to persist after reload")
	}
}

func TestJSONUMStorePersistsMultiUserMultiDeviceLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "um-multi.json")
	um, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("NewUserManagerWithStore failed: %v", err)
	}
	alice, err := um.CreateUser("alice")
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	bob, err := um.CreateUser("bob")
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}
	aliceEnroll1, _ := um.CreateEnrollment(alice.UserID, time.Minute)
	aliceEnroll2, _ := um.CreateEnrollment(alice.UserID, time.Minute)
	bobEnroll1, _ := um.CreateEnrollment(bob.UserID, time.Minute)
	bobEnroll2, _ := um.CreateEnrollment(bob.UserID, time.Minute)

	alicePub1 := []byte("alice-device-pk-1")
	alicePub2 := []byte("alice-device-pk-2")
	bobPub1 := []byte("bob-device-pk-1")
	bobPub2 := []byte("bob-device-pk-2")
	if _, err := um.BindDeviceByEnrollment(aliceEnroll1.Code, "alice-dev-1", alicePub1, "ed25519"); err != nil {
		t.Fatalf("bind alice dev1 failed: %v", err)
	}
	if _, err := um.BindDeviceByEnrollment(aliceEnroll2.Code, "alice-dev-2", alicePub2, "ed25519"); err != nil {
		t.Fatalf("bind alice dev2 failed: %v", err)
	}
	if _, err := um.BindDeviceByEnrollment(bobEnroll1.Code, "bob-dev-1", bobPub1, "ed25519"); err != nil {
		t.Fatalf("bind bob dev1 failed: %v", err)
	}
	if _, err := um.BindDeviceByEnrollment(bobEnroll2.Code, "bob-dev-2", bobPub2, "ed25519"); err != nil {
		t.Fatalf("bind bob dev2 failed: %v", err)
	}

	umReloaded, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("reload NewUserManagerWithStore failed: %v", err)
	}
	cases := []struct {
		name      string
		pub       []byte
		expectUID string
	}{
		{name: "alice-dev-1", pub: alicePub1, expectUID: alice.UserID},
		{name: "alice-dev-2", pub: alicePub2, expectUID: alice.UserID},
		{name: "bob-dev-1", pub: bobPub1, expectUID: bob.UserID},
		{name: "bob-dev-2", pub: bobPub2, expectUID: bob.UserID},
	}
	for _, tc := range cases {
		got, ok := umReloaded.FindUserByDevicePubKey(tc.pub, "ed25519")
		if !ok {
			t.Fatalf("lookup failed for %s", tc.name)
		}
		if got.UserID != tc.expectUID {
			t.Fatalf("lookup %s got user %s expect %s", tc.name, got.UserID, tc.expectUID)
		}
	}
}

func TestJSONUMStorePersistsAuthedDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "um-certified.json")
	um, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("NewUserManagerWithStore failed: %v", err)
	}
	user, _ := um.CreateUser("u")
	tk, err := um.IssueDeviceTicket(user.UserID, "g1", time.Minute)
	if err != nil {
		t.Fatalf("IssueDeviceTicket failed: %v", err)
	}
	if _, err := um.AuthDevice(user.UserID, "g1", "dev-1", tk.Ticket, []byte("pk-dev-1")); err != nil {
		t.Fatalf("AuthDevice failed: %v", err)
	}
	umReloaded, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !umReloaded.IsAuthedDevice(tk.GroupName, "dev-1") {
		t.Fatalf("expected authed device persisted")
	}
}

func TestUserManagerRestoreNormalizesAuthedDeviceKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "um-certified-normalize.json")
	store := NewJSONUMStore(path)
	snapshot := UMSnapshot{
		CertifiedDevices: map[string]UMAuthDevice{
			"dev-1": {
				UserID:       "u-1",
				GroupName:    "g1.ms.net",
				DeviceID:     "dev-1",
				PubKeyHex:    "pk",
				AuthedAt:     time.Now(),
				AuthExpireAt: time.Now().Add(time.Hour),
			},
		},
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	um, err := NewUserManagerWithStore(store)
	if err != nil {
		t.Fatalf("NewUserManagerWithStore failed: %v", err)
	}
	if !um.IsAuthedDevice("g1.ms.net", "dev-1") {
		t.Fatalf("expected authed device lookup to use normalized group|device key")
	}
}
