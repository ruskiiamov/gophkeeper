package access

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
	"golang.org/x/crypto/bcrypt"
)

const (
	ttl = 30 * time.Minute
	lockedSuffix = "-locked"
)

type serverManager struct {
	db     dbConnector
	secret string
}

type dbConnector interface {
	AddUser(ctx context.Context, login, passHash string) (id string, err error)
	GetUser(ctx context.Context, login string) (*dto.User, error)
	GetAndUpdatePassHash(ctx context.Context, userID string, passHashCh chan<- string, lockedPassHashCh <-chan string, errCh chan<- error)
	UpdatePassHash(ctx context.Context, userID, passHash string) error
}

func NewServerManager(secret string, db dbConnector) *serverManager {
	return &serverManager{
		db:     db,
		secret: secret,
	}
}

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

	return userID, nil
}

func (s *serverManager) CheckAndLockUser(ctx context.Context, userID, password string) error {
	passHashCh := make(chan string)
	lockedPassHashCh := make(chan string)
	errCh := make(chan error)

	go s.db.GetAndUpdatePassHash(ctx, userID, passHashCh, lockedPassHashCh, errCh)

	passHash := <-passHashCh
	if err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(password)); err != nil {
		return errs.ErrWrongPassword
	}

	lockedPassHashCh <- passHash + lockedSuffix

	return <-errCh
}

func (s *serverManager) UnlockUser(ctx context.Context, userID string) error {
	passHashCh := make(chan string)
	initialPassHashCh := make(chan string)
	errCh := make(chan error)

	go s.db.GetAndUpdatePassHash(ctx, userID, passHashCh, initialPassHashCh, errCh)

	passHash := <-passHashCh
	if !strings.HasSuffix(passHash, lockedSuffix) {
		return nil
	}

	initialPassHashCh <- strings.TrimSuffix(passHash, lockedSuffix)

	return <-errCh
}

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
