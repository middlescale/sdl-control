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

func NewWithDB(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }
