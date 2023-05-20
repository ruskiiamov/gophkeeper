package errs

import "errors"

var (
	ErrUserExists      = errors.New("user exists")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrWrongPassword   = errors.New("wrong password")
	ErrNotFound        = errors.New("not found")
	ErrLocked          = errors.New("entity is locked")
)
