package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

type WebUserProfile struct {
	SDLUserID   string
	Email       string
	DisplayName string
}

type ExitNodeApproval struct {
	UserID   string
	DeviceID string
}

func Open(databaseURL string) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Store{db: db}, nil
}

func (s *Store) ListWebUserProfiles() ([]WebUserProfile, error) {
	rows, err := s.db.Query(`SELECT a.sdl_user_id, u.email, u.display_name
		FROM sdl_accounts a JOIN users u ON u.id = a.user_id`)
	if err != nil {
		return nil, fmt.Errorf("list web user profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]WebUserProfile, 0)
	for rows.Next() {
		var profile WebUserProfile
		if err := rows.Scan(&profile.SDLUserID, &profile.Email, &profile.DisplayName); err != nil {
			return nil, fmt.Errorf("scan web user profile: %w", err)
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate web user profiles: %w", err)
	}
	return profiles, nil
}

func (s *Store) ListActiveExitNodeApprovals() ([]ExitNodeApproval, error) {
	rows, err := s.db.Query(`SELECT user_id, device_id FROM control_exit_node_approvals WHERE revoked_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list active exit-node approvals: %w", err)
	}
	defer rows.Close()

	approvals := make([]ExitNodeApproval, 0)
	for rows.Next() {
		var approval ExitNodeApproval
		if err := rows.Scan(&approval.UserID, &approval.DeviceID); err != nil {
			return nil, fmt.Errorf("scan exit-node approval: %w", err)
		}
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exit-node approvals: %w", err)
	}
	return approvals, nil
}

func (s *Store) ApproveExitNode(userID, deviceID, approvedBy string) error {
	if _, err := s.db.Exec(`
		INSERT INTO control_exit_node_approvals (user_id, device_id, approved_by, approved_at, revoked_at, updated_at)
		VALUES ($1, $2, $3, now(), NULL, now())
		ON CONFLICT (user_id, device_id) DO UPDATE
		SET approved_by = EXCLUDED.approved_by,
			approved_at = now(),
			revoked_at = NULL,
			updated_at = now()
	`, userID, deviceID, approvedBy); err != nil {
		return fmt.Errorf("approve exit-node: %w", err)
	}
	return nil
}

func (s *Store) RevokeExitNode(userID, deviceID string) error {
	res, err := s.db.Exec(`
		UPDATE control_exit_node_approvals
		SET revoked_at = now(), updated_at = now()
		WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL
	`, userID, deviceID)
	if err != nil {
		return fmt.Errorf("revoke exit-node: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke exit-node rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func NewWithDB(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }
