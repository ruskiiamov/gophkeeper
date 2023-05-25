// Package errs is the shared errors for the whole application.
package errs

import "errors"

var (
	// User already exists.
	ErrUserExists = errors.New("user exists")

	// Wrong credentials or access token is not valid.
	ErrUnauthenticated = errors.New("unauthenticated")

	// Provided password is wrong.
	ErrWrongPassword = errors.New("wrong password")

	// Entity not found.
	ErrNotFound = errors.New("not found")

	// Entity locked.
	ErrLocked = errors.New("entity is locked")
)
