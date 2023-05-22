// Package access is the user access logic for client ant server.
package access

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
	"golang.org/x/exp/slices"
)

type storage interface {
	GetUserCreds(ctx context.Context, login string) (*dto.Creds, error)
	AddUser(ctx context.Context, id, login string, key []byte) (*dto.Creds, error)
	AuthenticateUser(ctx context.Context, login, token string) error
	GetAuthenticatedUserCreds(ctx context.Context) (*dto.Creds, error)
	UpdateUserKey(ctx context.Context, login string, key []byte) error
	Logout(ctx context.Context) error
}

type provider interface {
	Register(ctx context.Context, login, password string) (id string, err error)
	Login(ctx context.Context, login, password string) (id, token string, err error)
	UpdatePass(ctx context.Context, token, oldPassword, newPassword string) error
}

type clientManager struct {
	storage  storage
	provider provider
}

// NewClientManager returns object that provides all necessary methods
// for access management on client side.
func NewClientManager(s storage, p provider) *clientManager {
	return &clientManager{
		storage:  s,
		provider: p,
	}
}

// Register creates new user on client side if it does not exist on server side.
// Provided creds are used for cipher key generation.
func (c *clientManager) Register(ctx context.Context, login, password string) error {
	creds, err := c.storage.GetUserCreds(ctx, login)
	if err != nil && !errors.Is(err, errs.ErrNotFound) {
		return fmt.Errorf("storage get user error: %w", err)
	}
	if creds != nil {
		return errors.New("user already exists in local storage")
	}

	serverPass := getServerPass(password)
	key := c.GetKey(ctx, login, password)

	id, err := c.provider.Register(ctx, login, serverPass)
	if err != nil {
		return fmt.Errorf("provider register error: %w", err)
	}

	_, err = c.storage.AddUser(ctx, id, login, key)
	if err != nil {
		return fmt.Errorf("storage add user error: %w", err)
	}

	return nil
}

// Login authenticates user on server side and saves the access token for
// following data synchronization. If the provided valid creds are differ from
// the local stored creds, the credsNotChanged is false.
func (c *clientManager) Login(ctx context.Context, login, password string) (creds *dto.Creds, credsNotChanged bool, err error) {
	serverPass := getServerPass(password)
	key := c.GetKey(ctx, login, password)

	id, token, err := c.provider.Login(ctx, login, serverPass)
	if err != nil {
		return nil, false, fmt.Errorf("provider login error: %w", err)
	}

	creds, err = c.storage.GetUserCreds(ctx, login)
	if err != nil {
		return nil, false, fmt.Errorf("storage get user error: %w", err)
	}

	if creds == nil {
		creds, err = c.storage.AddUser(ctx, id, login, key)
		if err != nil {
			return nil, false, fmt.Errorf("storage add user error: %w", err)
		}
	}

	creds.Token = token

	if slices.Equal(creds.Key, key) {
		if err := c.storage.AuthenticateUser(ctx, login, token); err != nil {
			return nil, false, fmt.Errorf("storage authenticate error: %w", err)
		}
		return creds, true, nil
	}

	creds.Key = key

	return creds, false, nil
}

// GetCreds returns creds for current authenticated user.
func (c *clientManager) GetCreds(ctx context.Context) (*dto.Creds, error) {
	creds, err := c.storage.GetAuthenticatedUserCreds(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage get authenticated user error: %w", err)
	}

	return creds, nil
}

// GetCredsByLogin returns creds for user with provided login.
func (c *clientManager) GetCredsByLogin(ctx context.Context, login string) (*dto.Creds, error) {
	creds, err := c.storage.GetUserCreds(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("storage get user error: %w", err)
	}

	return creds, nil
}

// GetKey returns the generated cipher key from the provided creds.
func (c *clientManager) GetKey(ctx context.Context, login, password string) []byte {
	h := md5.New()
	h.Write([]byte(login))
	left := h.Sum(nil)

	h.Reset()
	h.Write([]byte(password))
	right := h.Sum(nil)

	return append(left, right...)
}

// UpdateCredsAndAuthenticate updates user cipher key and saves access token for the
// following synchronizations.
func (c *clientManager) UpdateCredsAndAuthenticate(ctx context.Context, login, password, token string) error {
	key := c.GetKey(ctx, login, password)

	if err := c.storage.UpdateUserKey(ctx, login, key); err != nil {
		return fmt.Errorf("storage update user key error: %w", err)
	}

	if err := c.storage.AuthenticateUser(ctx, login, token); err != nil {
		return fmt.Errorf("storage authenticate user error: %w", err)
	}

	return nil
}

// UpdatePass updates user password on the server side.
func (c *clientManager) UpdatePass(ctx context.Context, creds *dto.Creds, oldPassword, newPassword string) error {
	oldServerPass := getServerPass(oldPassword)
	newServerPass := getServerPass(newPassword)

	if err := c.provider.UpdatePass(ctx, creds.Token, oldServerPass, newServerPass); err != nil {
		return fmt.Errorf("provider update pass error: %w", err)
	}

	return nil
}

// Logout revokes authentication for current authenticated user.
func (c *clientManager) Logout(ctx context.Context) error {
	if err := c.storage.Logout(ctx); err != nil {
		return fmt.Errorf("storage logout error: %w", err)
	}

	return nil
}

func getServerPass(password string) string {
	h := sha256.New()
	h.Write([]byte(password))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
