// Package db is the DB connector.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
)

const (
	source = "file://internal/db/migrations"
	ttl    = 2 * time.Minute
)

type connector struct {
	pool *pgxpool.Pool
}

// NewConnector returns the connector object with all necessary methods
// for data storing.
func NewConnector(ctx context.Context, dsn string) (*connector, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool creation error: %w", err)
	}

	m, err := migrate.New(source, dsn)
	if err != nil {
		return nil, fmt.Errorf("migrate creation error: %w", err)
	}

	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("db migration error: %w", err)
	}

	return &connector{pool: pool}, nil
}

// Close makes all DB connections closing.
func (c *connector) Close() {
	c.pool.Close()
}

// AddUser adds user data to the DB and returns generated UUID.
func (c *connector) AddUser(ctx context.Context, login, passHash string) (id string, err error) {
	err = c.pool.QueryRow(
		ctx,
		`INSERT INTO users (login, pass_hash) VALUES ($1, $2) 
		ON CONFLICT (login) DO NOTHING RETURNING id;`,
		login,
		passHash,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrUserExists
	}
	if err != nil {
		return "", fmt.Errorf("insert user error: %w", err)
	}

	return id, nil
}

// GetUser returns user data by the login.
func (c *connector) GetUser(ctx context.Context, login string) (*dto.User, error) {
	user := &dto.User{Login: login}

	err := c.pool.QueryRow(
		ctx,
		`SELECT id, pass_hash, locked, locked_until FROM users WHERE login = $1;`,
		login,
	).Scan(&(user.ID), &(user.PassHash), &(user.Locked), &(user.LockedUntil))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select user error: %w", err)
	}

	if user.Locked && user.LockedUntil.After(time.Now()) {
		return nil, errs.ErrNotFound
	}

	return user, nil
}

// GetUserByID returns user data by the user id.
func (c *connector) GetUserByID(ctx context.Context, userID string) (*dto.User, error) {
	user := &dto.User{ID: userID}

	err := c.pool.QueryRow(
		ctx,
		`SELECT login, pass_hash, locked, locked_until FROM users WHERE id = $1;`,
		userID,
	).Scan(&(user.Login), &(user.PassHash), &(user.Locked), &(user.LockedUntil))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select user error: %w", err)
	}

	if user.Locked && user.LockedUntil.After(time.Now()) {
		return nil, errs.ErrNotFound
	}

	return user, nil
}

// CheckAndLockUser makes transaction with the check and lock user.
func (c *connector) CheckAndLockUser(ctx context.Context, userID string, passHashCh chan<- string, confirmationCh <-chan bool, errCh chan<- error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		errCh <- fmt.Errorf("transaction begin error: %w", err)
		return
	}
	defer tx.Rollback(ctx)

	var passHash string
	var locked bool
	var lockedUntil time.Time
	err = tx.QueryRow(
		ctx,
		`SELECT pass_hash, locked, locked_until FROM users WHERE id = $1;`,
		userID,
	).Scan(&passHash, &locked, &lockedUntil)
	if err != nil {
		errCh <- fmt.Errorf("select user error: %w", err)
		return
	}

	if locked && lockedUntil.After(time.Now()) {
		errCh <- errs.ErrLocked
		return
	}

	passHashCh <- passHash

	var confirmation bool
	select {
	case <-ctx.Done():
		errCh <- fmt.Errorf("context canceled")
		return
	case confirmation = <-confirmationCh:
	}

	if !confirmation {
		errCh <- fmt.Errorf("lock is not confirmed")
		return
	}

	_, err = tx.Exec(
		ctx,
		`UPDATE users SET locked = TRUE, locked_until = $1 WHERE id = $2;`,
		time.Now().Add(ttl),
		userID,
	)
	if err != nil {
		errCh <- fmt.Errorf("update user error: %w", err)
		return
	}

	if err = tx.Commit(ctx); err != nil {
		errCh <- fmt.Errorf("transaction commit error: %w", err)
		return
	}

	errCh <- nil
}

// UnlockUser revokes user lock.
func (c *connector) UnlockUser(ctx context.Context, userID string) error {
	_, err := c.pool.Exec(
		ctx,
		`UPDATE users SET locked = FALSE, locked_until = $1 WHERE id = $2;`,
		time.Now(),
		userID,
	)

	if err != nil {
		return fmt.Errorf("update user error: %w", err)
	}

	return nil
}

// UpdatePassHash updates user password hash.
func (c *connector) UpdatePassHash(ctx context.Context, userID, passHash string) error {
	_, err := c.pool.Exec(
		ctx,
		`UPDATE users SET pass_hash = $1 WHERE id = $2;`,
		passHash,
		userID,
	)

	if err != nil {
		return fmt.Errorf("update user error: %w", err)
	}

	return nil
}

// CheckAndLockEntry makes transaction with check and lock for the entry.
func (c *connector) CheckAndLockEntry(ctx context.Context, id, userID string) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("transaction begin error: %w", err)
	}
	defer tx.Rollback(ctx)

	var locked bool
	var lockedUntil time.Time
	err = tx.QueryRow(
		ctx,
		`SELECT locked, locked_until FROM entries WHERE id = $1 AND user_id = $2;`,
		id,
		userID,
	).Scan(&locked, &lockedUntil)
	if err != nil {
		return fmt.Errorf("select entry error: %w", err)
	}

	if locked && lockedUntil.After(time.Now()) {
		return errs.ErrLocked
	}

	_, err = tx.Exec(
		ctx,
		`UPDATE entries SET locked = TRUE, locked_until = $1 WHERE id = $2 AND user_id = $3;`,
		time.Now().Add(ttl),
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("update entry error: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("transaction commit error: %w", err)
	}

	return nil
}

// CheckAndLockEntries makes transaction with check and lock for the all user entries.
func (c *connector) CheckAndLockEntries(ctx context.Context, userID string) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("transaction begin error: %w", err)
	}
	defer tx.Rollback(ctx)

	var id string
	err = tx.QueryRow(
		ctx,
		`SELECT id FROM entries WHERE user_id = $1 AND locked = TRUE AND locked_until > $2;`,
		userID,
		time.Now(),
	).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("select entry error: %w", err)
	}
	if err == nil {
		return errs.ErrLocked
	}

	_, err = tx.Exec(
		ctx,
		`UPDATE entries SET locked = TRUE, locked_until = $1 WHERE user_id = $2;`,
		time.Now().Add(ttl),
		userID,
	)
	if err != nil {
		return fmt.Errorf("update entries error: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction error: %s", err)
	}

	return nil
}

// UnlockEntry revokes entry lock.
func (c *connector) UnlockEntry(ctx context.Context, id, userID string) error {
	_, err := c.pool.Exec(
		ctx,
		`UPDATE entries SET locked = FALSE, locked_until = $1 WHERE id = $2 AND user_id = $3;`,
		time.Now(),
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("update entries error: %w", err)
	}

	return nil
}

// UnlockEntries revokes lock for all user entries.
func (c *connector) UnlockEntries(ctx context.Context, userID string) error {
	_, err := c.pool.Exec(
		ctx,
		`UPDATE entries SET locked = FALSE, locked_until = $1 WHERE user_id = $2;`,
		time.Now(),
		userID,
	)
	if err != nil {
		return fmt.Errorf("update entries error: %w", err)
	}

	return nil
}

// GetEntries returns all user entries metadata.
func (c *connector) GetEntries(ctx context.Context, userID string) ([]*dto.ServerEntry, error) {
	rows, err := c.pool.Query(
		ctx,
		`SELECT id, metadata FROM entries WHERE user_id = $1;`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("select entries error: %w", err)
	}

	entries := make([]*dto.ServerEntry, 0)
	for rows.Next() {
		entry := &dto.ServerEntry{UserID: userID}
		err = rows.Scan(&(entry.ID), &(entry.Metadata))
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// ForceDeleteEntry deletes rows from the entry storage.
func (c *connector) ForceDeleteEntry(ctx context.Context, id, userID string) error {
	_, err := c.pool.Exec(
		ctx,
		`DELETE FROM entries WHERE id = $1 AND user_id = $2;`,
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("delete entry error: %w", err)
	}

	return nil
}

// AddEntry adds new row to the entry storage.
func (c *connector) AddEntry(ctx context.Context, entry *dto.ServerEntry) error {
	_, err := c.pool.Exec(
		ctx,
		`INSERT INTO entries (id, user_id, metadata) VALUES ($1, $2, $3);`,
		entry.ID,
		entry.UserID,
		entry.Metadata,
	)
	if err != nil {
		return fmt.Errorf("insert entry error: %w", err)
	}

	return nil
}

// GetEntry returns entry metadata.
func (c *connector) GetEntry(ctx context.Context, id, userID string) (*dto.ServerEntry, error) {
	entry := &dto.ServerEntry{ID: id, UserID: userID}

	err := c.pool.QueryRow(
		ctx,
		`SELECT metadata FROM entries WHERE id = $1 AND user_id = $2;`,
		id,
		userID,
	).Scan(&(entry.Metadata))
	if err != nil {
		return nil, fmt.Errorf("select entry error: %w", err)
	}

	return entry, nil
}

// UpdateEntry updates entry metadata.
func (c *connector) UpdateEntry(ctx context.Context, entry *dto.ServerEntry) error {
	_, err := c.pool.Exec(
		ctx,
		`UPDATE entries SET metadata = $1 WHERE id = $2 AND user_id = $3;`,
		entry.Metadata,
		entry.ID,
		entry.UserID,
	)
	if err != nil {
		return fmt.Errorf("update entry error: %w", err)
	}

	return nil
}
