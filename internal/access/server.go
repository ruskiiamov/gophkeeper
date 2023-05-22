package access

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
	"golang.org/x/crypto/bcrypt"
)

const (
	ttl          = 6 * time.Hour
	lockedSuffix = "-locked"
)

type serverManager struct {
	db     dbConnector
	secret string
}

type dbConnector interface {
	AddUser(ctx context.Context, login, passHash string) (id string, err error)
	GetUser(ctx context.Context, login string) (*dto.User, error)
	GetUserByID(ctx context.Context, userID string) (*dto.User, error)
	CheckAndLockUser(ctx context.Context, userID string, passHashCh chan<- string, confirmationCh <-chan bool, errCh chan<- error)
	UnlockUser(ctx context.Context, userID string) error
	UpdatePassHash(ctx context.Context, userID, passHash string) error
}

// NewServerManager returns object that provides all necessary methods
// for access management on server side.
func NewServerManager(secret string, db dbConnector) *serverManager {
	return &serverManager{
		db:     db,
		secret: secret,
	}
}

// Register creates new user on server side if it does not exist in the DB.
func (s *serverManager) Register(ctx context.Context, login, password string) (id string, err error) {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("pass hash error: %w", err)
	}

	id, err = s.db.AddUser(ctx, login, string(passHash))
	if err != nil {
		return "", fmt.Errorf("db add user error: %w", err)
	}

	return id, nil
}

// Login authenticates user on server side and generates new access token for
// following data synchronization.
func (s *serverManager) Login(ctx context.Context, login, password string) (id, token string, err error) {
	user, err := s.db.GetUser(ctx, login)
	if errors.Is(err, errs.ErrNotFound) {
		return "", "", errs.ErrUnauthenticated
	}
	if err != nil {
		return "", "", fmt.Errorf("db get user error: %w", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		return "", "", errs.ErrUnauthenticated
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    user.ID,
		"created_at": strconv.FormatInt(time.Now().Unix(), 10),
	})

	token, err = jwtToken.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", fmt.Errorf("jwt signing error: %w", err)
	}

	return user.ID, token, nil
}

// Auth checks provided access token and returns its owner id. If the access token
// was created before the last user password update, this token is considered as not valid.
func (s *serverManager) Auth(ctx context.Context, token string) (userID string, err error) {
	jwtToken, _ := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte(s.secret), nil
	})

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return "", errs.ErrUnauthenticated
	}

	createdAt, ok := claims["created_at"].(string)
	if !ok {
		return "", errs.ErrUnauthenticated
	}

	intCreatedAt, err := strconv.ParseInt(createdAt, 10, 64)
	if err != nil {
		return "", errs.ErrUnauthenticated
	}

	if time.Unix(intCreatedAt, 0).Add(ttl).Before(time.Now()) {
		return "", errs.ErrUnauthenticated
	}

	userID, ok = claims["user_id"].(string)
	if !ok {
		return "", errs.ErrUnauthenticated
	}

	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("db get user by id error: %w", err)
	}

	if time.Unix(intCreatedAt, 0).Before(user.LockedUntil) {
		return "", errs.ErrUnauthenticated
	}

	return userID, nil
}

// CheckAndLockUser checks the DB lock for user and locks it in case of user availability.
func (s *serverManager) CheckAndLockUser(ctx context.Context, userID, password string) error {
	passHashCh := make(chan string, 1)
	confirmationCh := make(chan bool, 1)
	errCh := make(chan error, 1)

	go s.db.CheckAndLockUser(ctx, userID, passHashCh, confirmationCh, errCh)

	var passHash string
	var err error
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled")
	case err = <-errCh:
		if err != nil {
			return fmt.Errorf("db check and lock user error: %w", err)
		}
	case passHash = <-passHashCh:
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(password)); err != nil {
		confirmationCh <- false
		return errs.ErrWrongPassword
	}

	confirmationCh <- true

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled")
	case err = <-errCh:
	}

	return err
}

// UnlockUser opens the lock for provided user.
func (s *serverManager) UnlockUser(ctx context.Context, userID string) error {
	err := s.db.UnlockUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("db unlock user error: %w", err)
	}

	return nil
}

// UpdatePass updates the stored password hash for the user.
func (s *serverManager) UpdatePass(ctx context.Context, userID, password string) error {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("pass hash error: %w", err)
	}

	if err = s.db.UpdatePassHash(ctx, userID, string(passHash)); err != nil {
		return fmt.Errorf("db update pass hash error: %w", err)
	}

	return nil
}
