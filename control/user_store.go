package control

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type UMStore interface {
	Load() (UMSnapshot, error)
	Save(UMSnapshot) error
}

type UMSnapshot struct {
	UserSeq          uint64                    `json:"user_seq"`
	EnrollmentSeq    uint64                    `json:"enrollment_seq"`
	Users            map[string]UMUser         `json:"users"`
	Policies         map[string]UMPolicy       `json:"policies"`
	Enrollments      map[string]UMEnrollment   `json:"enrollments"`
	DeviceByPubKey   map[string]UMDevice       `json:"device_by_pub_key"`
	CertifiedDevices map[string]UMAuthDevice   `json:"certified_devices"`
	DeviceTickets    map[string]UMDeviceTicket `json:"device_tickets"`
}

type JSONUMStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONUMStore(path string) *JSONUMStore {
	return &JSONUMStore{path: path}
}

func (s *JSONUMStore) Load() (UMSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return UMSnapshot{}, nil
		}
		return UMSnapshot{}, fmt.Errorf("read um json: %w", err)
	}
	var snapshot UMSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return UMSnapshot{}, fmt.Errorf("unmarshal um json: %w", err)
	}
	return snapshot, nil
}

func (s *JSONUMStore) Save(snapshot UMSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir um json dir: %w", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal um json: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write um json temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename um json temp file: %w", err)
	}
	return nil
}
