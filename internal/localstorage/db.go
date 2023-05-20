package localstorage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/enum"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
)

type storage struct {
	conn *sql.DB
}

func New(dsn string) (*storage, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db conn error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("db ping error: %w", err)
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY, 
		login TEXT NOT NULL, 
		key TEXT NOT NULL, 
		token TEXT, 
		authenticated INTEGER DEFAULT 0 NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create users table error: %w", err)
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS entries (
		id TEXT NOT NULL, 
		user_id TEXT NOT NULL, 
		type INTEGER,
		file_name TEXT, 
		description TEXT, 
		checksum TEXT, 
		deleted INTEGER DEFAULT 0 NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (id, user_id),
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	if err != nil {
		return nil, fmt.Errorf("create entries table error: %w", err)
	}

	return &storage{conn: db}, nil
}

func (s *storage) Close() {
	s.conn.Close()
}

func (s *storage) GetUserCreds(ctx context.Context, login string) (*dto.Creds, error) {
	creds := new(dto.Creds)
	var key string
	var token sql.NullString

	err := s.conn.QueryRowContext(
		ctx, `SELECT id, key, token FROM users WHERE login = ?;`, login,
	).Scan(&(creds.UserID), &key, &token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select row error: %w", err)
	}

	creds.Key, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("key decoding error: %w", err)
	}

	if token.Valid {
		creds.Token = token.String
	}

	return creds, nil
}

func (s *storage) AddUser(ctx context.Context, id, login string, key []byte) (*dto.Creds, error) {
	strKey := base64.StdEncoding.EncodeToString(key)

	_, err := s.conn.ExecContext(
		ctx, `INSERT INTO users (id, login, key) VALUES(?, ?, ?);`, id, login, strKey,
	)
	if err != nil {
		return nil, fmt.Errorf("insert row error: %w", err)
	}

	return &dto.Creds{
		UserID: id,
		Key:    key,
	}, nil
}

func (s *storage) AuthenticateUser(ctx context.Context, login, token string) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET authenticated = 0;`)
	if err != nil {
		return fmt.Errorf("update users error: %w", err)
	}

	_, err = s.conn.ExecContext(
		ctx, `UPDATE users SET authenticated = 1, token = ? WHERE login = ?;`, token, login,
	)
	if err != nil {
		return fmt.Errorf("update user error: %w", err)
	}

	return nil
}

func (s *storage) GetAuthenticatedUserCreds(ctx context.Context) (*dto.Creds, error) {
	creds := new(dto.Creds)
	var key string
	var token sql.NullString

	err := s.conn.QueryRowContext(
		ctx, `SELECT id, key, token FROM users WHERE authenticated = 1;`,
	).Scan(&(creds.UserID), &key, &token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errs.ErrUnauthenticated
	}
	if err != nil {
		return nil, fmt.Errorf("select row error: %w", err)
	}

	creds.Key, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("key decoding error: %w", err)
	}

	if token.Valid {
		creds.Token = token.String
	}

	return creds, nil
}

func (s *storage) UpdateUserKey(ctx context.Context, login string, key []byte) error {
	strKey := base64.StdEncoding.EncodeToString(key)

	_, err := s.conn.ExecContext(
		ctx, `UPDATE users SET key = ? WHERE login = ?`, strKey, login,
	)
	if err != nil {
		return fmt.Errorf("update user error: %w", err)
	}

	return nil
}

func (s *storage) Logout(ctx context.Context) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE users SET authenticated = 0;`)
	if err != nil {
		return fmt.Errorf("update users error: %w", err)
	}

	return nil
}

func (s *storage) GetEntries(ctx context.Context, userID string) ([]*dto.ClientEntry, error) {
	entries := make([]*dto.ClientEntry, 0)

	rows, err := s.conn.QueryContext(
		ctx,
		`SELECT id, type, file_name, description, checksum, deleted, updated_at
		FROM entries WHERE user_id = ?;`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("select rows error: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			entryType                       sql.NullInt32
			fileName, description, checksum sql.NullString
			deleted, updatedAt              int
		)

		entry := &dto.ClientEntry{UserID: userID}

		err = rows.Scan(&(entry.ID), &entryType, &fileName, &description, &checksum, &deleted, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("rows scan error: %w", err)
		}

		if entryType.Valid {
			entry.Type = enum.Type(entryType.Int32)
		}

		if fileName.Valid {
			entry.FileName = fileName.String
		}

		if description.Valid {
			entry.Description = description.String
		}

		if checksum.Valid {
			entry.Checksum = checksum.String
		}

		if deleted == 1 {
			entry.Deleted = true
		}

		entry.UpdatedAt = time.Unix(int64(updatedAt), 0)

		entries = append(entries, entry)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return entries, nil
}

func (s *storage) AddEntry(ctx context.Context, entry *dto.ClientEntry) error {
	var entryType sql.NullInt32
	if entry.Type.Valid() {
		entryType = sql.NullInt32{Int32: int32(entry.Type), Valid: true}
	}

	var fileName sql.NullString
	if entry.FileName != "" {
		fileName = sql.NullString{String: entry.FileName, Valid: true}
	}

	var description sql.NullString
	if entry.Description != "" {
		description = sql.NullString{String: entry.Description, Valid: true}
	}

	var checksum sql.NullString
	if entry.Checksum != "" {
		checksum = sql.NullString{String: entry.Checksum, Valid: true}
	}

	_, err := s.conn.ExecContext(
		ctx,
		`INSERT INTO entries (id, user_id, type, file_name, description, checksum, updated_at) 
		VALUES(?, ?, ?, ?, ?, ?, ?);`,
		entry.ID,
		entry.UserID,
		entryType,
		fileName,
		description,
		checksum,
		time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert row error: %w", err)
	}

	return nil
}

func (s *storage) GetEntry(ctx context.Context, userID, id string) (*dto.ClientEntry, error) {
	var (
		entryType                       sql.NullInt32
		fileName, description, checksum sql.NullString
		deleted, updatedAt              int
	)

	err := s.conn.QueryRowContext(
		ctx,
		`SELECT type, file_name, description, checksum, deleted, updated_at
		FROM entries WHERE id = ? AND user_id = ?;`,
		id,
		userID,
	).Scan(&entryType, &fileName, &description, &checksum, &deleted, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("select row error: %w", err)
	}

	entry := &dto.ClientEntry{ID: id, UserID: userID}

	if entryType.Valid {
		entry.Type = enum.Type(entryType.Int32)
	}

	if fileName.Valid {
		entry.FileName = fileName.String
	}

	if description.Valid {
		entry.Description = description.String
	}

	if checksum.Valid {
		entry.Checksum = checksum.String
	}

	if deleted == 1 {
		entry.Deleted = true
	}

	entry.UpdatedAt = time.Unix(int64(updatedAt), 0)

	return entry, nil
}

func (s *storage) AddOrUpdateEntry(ctx context.Context, entry *dto.ClientEntry) error {
	_, err := s.GetEntry(ctx, entry.UserID, entry.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return s.AddEntry(ctx, entry)
	}
	if err != nil {
		return fmt.Errorf("get entry error: %w", err)
	}

	var fileName sql.NullString
	if entry.FileName != "" {
		fileName = sql.NullString{String: entry.FileName, Valid: true}
	}

	var description sql.NullString
	if entry.Description != "" {
		description = sql.NullString{String: entry.Description, Valid: true}
	}

	var checksum sql.NullString
	if entry.Checksum != "" {
		checksum = sql.NullString{String: entry.Checksum, Valid: true}
	}

	_, err = s.conn.ExecContext(
		ctx,
		`UPDATE entries SET file_name = ?, description = ?, checksum = ?, updated_at = ? 
		WHERE id = ? AND user_id = ?;`,
		fileName,
		description,
		checksum,
		entry.UpdatedAt.Unix(),
		entry.ID,
		entry.UserID,
	)
	if err != nil {
		return fmt.Errorf("update row error: %w", err)
	}

	return nil
}

func (s *storage) UpdateChecksums(ctx context.Context, entries []*dto.ClientEntry) error {
	tx, err := s.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction error: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `UPDATE entries SET checksum = ? WHERE id = ? and user_id = ?;`)
	if err != nil {
		return fmt.Errorf("prepare statement error: %w", err)
	}
	defer stmt.Close()

	for _, entry := range entries {
		if _, err = stmt.ExecContext(ctx, entry.Checksum, entry.ID, entry.UserID); err != nil {
			return fmt.Errorf("statement exec error: %w", err)
		}
	}

	return tx.Commit()
}
