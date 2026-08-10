package control

import (
	"database/sql"
	"fmt"
)

type PostgresUMStore struct {
	db *sql.DB
}

func NewPostgresUMStore(db *sql.DB) *PostgresUMStore {
	return &PostgresUMStore{db: db}
}

func (s *PostgresUMStore) Load() (UMSnapshot, error) {
	snap := UMSnapshot{
		Users:            make(map[string]UMUser),
		Policies:         make(map[string]UMPolicy),
		Enrollments:      make(map[string]UMEnrollment),
		DeviceByPubKey:   make(map[string]UMDevice),
		CertifiedDevices: make(map[string]UMAuthDevice),
		DeviceTickets:    make(map[string]UMDeviceTicket),
	}

	rows, err := s.db.Query(`SELECT user_id, name, domain, created_at FROM um_users`)
	if err != nil {
		return snap, fmt.Errorf("load um_users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u UMUser
		if err := rows.Scan(&u.UserID, &u.Name, &u.Domain, &u.CreatedAt); err != nil {
			return snap, fmt.Errorf("scan um_user: %w", err)
		}
		snap.Users[u.UserID] = u
	}
	if err := rows.Err(); err != nil {
		return snap, err
	}

	pRows, err := s.db.Query(`SELECT user_id, group_name, user_expire_at_unix_ms, user_grace_period_seconds, allow_p2p, allow_relay, max_devices, enrollment_ttl_seconds, gateway_ticket_ttl_seconds, created_at, updated_at FROM um_policies`)
	if err != nil {
		return snap, fmt.Errorf("load um_policies: %w", err)
	}
	defer pRows.Close()
	for pRows.Next() {
		var p UMPolicy
		if err := pRows.Scan(&p.UserID, &p.GroupName, &p.UserExpireAtUnixMs, &p.UserGracePeriodSeconds, &p.AllowP2P, &p.AllowRelay, &p.MaxDevices, &p.EnrollmentTTLSeconds, &p.GatewayTicketTTLSeconds, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return snap, fmt.Errorf("scan um_policy: %w", err)
		}
		snap.Policies[p.UserID] = p
	}
	if err := pRows.Err(); err != nil {
		return snap, err
	}

	eRows, err := s.db.Query(`SELECT code, user_id, expire_at, used, created_at FROM um_enrollments`)
	if err != nil {
		return snap, fmt.Errorf("load um_enrollments: %w", err)
	}
	defer eRows.Close()
	for eRows.Next() {
		var e UMEnrollment
		if err := eRows.Scan(&e.Code, &e.UserID, &e.ExpireAt, &e.Used, &e.CreatedAt); err != nil {
			return snap, fmt.Errorf("scan um_enrollment: %w", err)
		}
		snap.Enrollments[e.Code] = e
	}
	if err := eRows.Err(); err != nil {
		return snap, err
	}

	dRows, err := s.db.Query(`SELECT pub_key_hex, user_id, device_id, display_name, created_at FROM um_devices`)
	if err != nil {
		return snap, fmt.Errorf("load um_devices: %w", err)
	}
	defer dRows.Close()
	for dRows.Next() {
		var d UMDevice
		if err := dRows.Scan(&d.PubKeyHex, &d.UserID, &d.DeviceID, &d.DisplayName, &d.CreatedAt); err != nil {
			return snap, fmt.Errorf("scan um_device: %w", err)
		}
		snap.DeviceByPubKey[d.PubKeyHex] = d
	}
	if err := dRows.Err(); err != nil {
		return snap, err
	}

	cRows, err := s.db.Query(`SELECT group_name, device_id, user_id, display_name, pub_key_hex, authed_at, auth_expire_at FROM um_certified_devices`)
	if err != nil {
		return snap, fmt.Errorf("load um_certified_devices: %w", err)
	}
	defer cRows.Close()
	for cRows.Next() {
		var c UMAuthDevice
		if err := cRows.Scan(&c.GroupName, &c.DeviceID, &c.UserID, &c.DisplayName, &c.PubKeyHex, &c.AuthedAt, &c.AuthExpireAt); err != nil {
			return snap, fmt.Errorf("scan um_certified_device: %w", err)
		}
		snap.CertifiedDevices[authedDeviceKey(c.GroupName, c.DeviceID)] = c
	}
	if err := cRows.Err(); err != nil {
		return snap, err
	}

	tRows, err := s.db.Query(`SELECT ticket, user_id, group_name, expire_at, used, created_at FROM um_device_tickets`)
	if err != nil {
		return snap, fmt.Errorf("load um_device_tickets: %w", err)
	}
	defer tRows.Close()
	for tRows.Next() {
		var t UMDeviceTicket
		if err := tRows.Scan(&t.Ticket, &t.UserID, &t.GroupName, &t.ExpireAt, &t.Used, &t.CreatedAt); err != nil {
			return snap, fmt.Errorf("scan um_device_ticket: %w", err)
		}
		snap.DeviceTickets[t.Ticket] = t
	}
	if err := tRows.Err(); err != nil {
		return snap, err
	}

	s.db.QueryRow(`SELECT seq_val FROM um_sequences WHERE seq_name = 'user_seq'`).Scan(&snap.UserSeq)
	s.db.QueryRow(`SELECT seq_val FROM um_sequences WHERE seq_name = 'enrollment_seq'`).Scan(&snap.EnrollmentSeq)

	return snap, nil
}

func (s *PostgresUMStore) Save(snap UMSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("save um begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, u := range snap.Users {
		if _, err := tx.Exec(`INSERT INTO um_users (user_id, name, domain, created_at) VALUES ($1,$2,$3,$4)
			ON CONFLICT (user_id) DO UPDATE SET name = EXCLUDED.name, domain = EXCLUDED.domain, created_at = EXCLUDED.created_at`,
			u.UserID, u.Name, u.Domain, u.CreatedAt); err != nil {
			return fmt.Errorf("insert um_user: %w", err)
		}
	}
	if err := deleteMissingStringKeys(tx, `SELECT user_id FROM um_users`, `DELETE FROM um_users WHERE user_id = $1`, snapshotStringKeys(snap.Users)); err != nil {
		return fmt.Errorf("delete stale um_users: %w", err)
	}

	for _, e := range snap.Enrollments {
		if _, err := tx.Exec(`INSERT INTO um_enrollments (code, user_id, expire_at, used, created_at) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (code) DO UPDATE SET user_id = EXCLUDED.user_id, expire_at = EXCLUDED.expire_at, used = EXCLUDED.used, created_at = EXCLUDED.created_at`,
			e.Code, e.UserID, e.ExpireAt, e.Used, e.CreatedAt); err != nil {
			return fmt.Errorf("insert um_enrollment: %w", err)
		}
	}
	if err := deleteMissingStringKeys(tx, `SELECT code FROM um_enrollments`, `DELETE FROM um_enrollments WHERE code = $1`, snapshotStringKeys(snap.Enrollments)); err != nil {
		return fmt.Errorf("delete stale um_enrollments: %w", err)
	}

	for _, d := range snap.DeviceByPubKey {
		if _, err := tx.Exec(`INSERT INTO um_devices (pub_key_hex, user_id, device_id, display_name, created_at) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (pub_key_hex) DO UPDATE SET user_id = EXCLUDED.user_id, device_id = EXCLUDED.device_id, display_name = EXCLUDED.display_name, created_at = EXCLUDED.created_at`,
			d.PubKeyHex, d.UserID, d.DeviceID, d.DisplayName, d.CreatedAt); err != nil {
			return fmt.Errorf("insert um_device: %w", err)
		}
	}
	if err := deleteMissingStringKeys(tx, `SELECT pub_key_hex FROM um_devices`, `DELETE FROM um_devices WHERE pub_key_hex = $1`, snapshotStringKeys(snap.DeviceByPubKey)); err != nil {
		return fmt.Errorf("delete stale um_devices: %w", err)
	}

	for _, c := range snap.CertifiedDevices {
		if _, err := tx.Exec(`INSERT INTO um_certified_devices (group_name, device_id, user_id, display_name, pub_key_hex, authed_at, auth_expire_at) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (group_name, device_id) DO UPDATE SET user_id = EXCLUDED.user_id, display_name = EXCLUDED.display_name, pub_key_hex = EXCLUDED.pub_key_hex, authed_at = EXCLUDED.authed_at, auth_expire_at = EXCLUDED.auth_expire_at`,
			c.GroupName, c.DeviceID, c.UserID, c.DisplayName, c.PubKeyHex, c.AuthedAt, c.AuthExpireAt); err != nil {
			return fmt.Errorf("insert um_certified_device: %w", err)
		}
	}
	if err := deleteMissingCertifiedDevices(tx, snap.CertifiedDevices); err != nil {
		return fmt.Errorf("delete stale um_certified_devices: %w", err)
	}

	for _, p := range snap.Policies {
		if _, err := tx.Exec(`INSERT INTO um_policies (
			user_id, group_name, user_expire_at_unix_ms, user_grace_period_seconds, allow_p2p, allow_relay,
			max_devices, enrollment_ttl_seconds, gateway_ticket_ttl_seconds, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (user_id) DO UPDATE SET
			group_name = EXCLUDED.group_name,
			user_expire_at_unix_ms = EXCLUDED.user_expire_at_unix_ms,
			user_grace_period_seconds = EXCLUDED.user_grace_period_seconds,
			allow_p2p = EXCLUDED.allow_p2p,
			allow_relay = EXCLUDED.allow_relay,
			max_devices = EXCLUDED.max_devices,
			enrollment_ttl_seconds = EXCLUDED.enrollment_ttl_seconds,
			gateway_ticket_ttl_seconds = EXCLUDED.gateway_ticket_ttl_seconds,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
			p.UserID, p.GroupName, p.UserExpireAtUnixMs, p.UserGracePeriodSeconds, p.AllowP2P, p.AllowRelay,
			p.MaxDevices, p.EnrollmentTTLSeconds, p.GatewayTicketTTLSeconds, p.CreatedAt, p.UpdatedAt); err != nil {
			return fmt.Errorf("insert um_policy: %w", err)
		}
	}
	if err := deleteMissingStringKeys(tx, `SELECT user_id FROM um_policies`, `DELETE FROM um_policies WHERE user_id = $1`, snapshotStringKeys(snap.Policies)); err != nil {
		return fmt.Errorf("delete stale um_policies: %w", err)
	}

	for _, t := range snap.DeviceTickets {
		if _, err := tx.Exec(`INSERT INTO um_device_tickets (ticket, user_id, group_name, expire_at, used, created_at) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (ticket) DO UPDATE SET user_id = EXCLUDED.user_id, group_name = EXCLUDED.group_name, expire_at = EXCLUDED.expire_at, used = EXCLUDED.used, created_at = EXCLUDED.created_at`,
			t.Ticket, t.UserID, t.GroupName, t.ExpireAt, t.Used, t.CreatedAt); err != nil {
			return fmt.Errorf("insert um_device_ticket: %w", err)
		}
	}
	if err := deleteMissingStringKeys(tx, `SELECT ticket FROM um_device_tickets`, `DELETE FROM um_device_tickets WHERE ticket = $1`, snapshotStringKeys(snap.DeviceTickets)); err != nil {
		return fmt.Errorf("delete stale um_device_tickets: %w", err)
	}

	if _, err := tx.Exec(`INSERT INTO um_sequences (seq_name, seq_val) VALUES ('user_seq', $1)
		ON CONFLICT (seq_name) DO UPDATE SET seq_val = EXCLUDED.seq_val`, snap.UserSeq); err != nil {
		return fmt.Errorf("update user_seq: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO um_sequences (seq_name, seq_val) VALUES ('enrollment_seq', $1)
		ON CONFLICT (seq_name) DO UPDATE SET seq_val = EXCLUDED.seq_val`, snap.EnrollmentSeq); err != nil {
		return fmt.Errorf("update enrollment_seq: %w", err)
	}

	return tx.Commit()
}

func snapshotStringKeys[T any](src map[string]T) map[string]struct{} {
	keys := make(map[string]struct{}, len(src))
	for key := range src {
		keys[key] = struct{}{}
	}
	return keys
}

func deleteMissingStringKeys(tx *sql.Tx, selectQuery, deleteStmt string, keep map[string]struct{}) error {
	rows, err := tx.Query(selectQuery)
	if err != nil {
		return err
	}
	var missing []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		if _, ok := keep[key]; ok {
			continue
		}
		missing = append(missing, key)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, key := range missing {
		if _, err := tx.Exec(deleteStmt, key); err != nil {
			return err
		}
	}
	return nil
}

func deleteMissingCertifiedDevices(tx *sql.Tx, keep map[string]UMAuthDevice) error {
	rows, err := tx.Query(`SELECT group_name, device_id FROM um_certified_devices`)
	if err != nil {
		return err
	}
	type certifiedKey struct {
		groupName string
		deviceID  string
	}
	var missing []certifiedKey
	for rows.Next() {
		var groupName string
		var deviceID string
		if err := rows.Scan(&groupName, &deviceID); err != nil {
			rows.Close()
			return err
		}
		if _, ok := keep[authedDeviceKey(groupName, deviceID)]; ok {
			continue
		}
		missing = append(missing, certifiedKey{groupName: groupName, deviceID: deviceID})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, key := range missing {
		if _, err := tx.Exec(`DELETE FROM um_certified_devices WHERE group_name = $1 AND device_id = $2`, key.groupName, key.deviceID); err != nil {
			return err
		}
	}
	return nil
}
