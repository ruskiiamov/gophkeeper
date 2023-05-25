// Package dto is the shared structs for the whole application.
package dto

import (
	"time"

	"github.com/ruskiiamov/gophkeeper/internal/enum"
)

// Creds is the struct of user credentials stored in the client side.
type Creds struct {
	// Global user ID.
	UserID string

	// Cipher key.
	Key []byte

	// Access token.
	Token string
}

// LogPass is the struct of login-password data type.
type LogPass struct {
	// Stored login.
	Login string

	// Stored password.
	Password string
}

// Card is the struct of bank card data type.
type Card struct {
	// Stored bank card number.
	Number string

	// Stored bank card owner.
	Owner string

	// Stored bank card expire date.
	Expire string

	// Stored bank card code.
	Code string

	// Stored bank card PIN.
	Pin string
}

// Metadata is the struct for client side entry metadata.
type Metadata struct {
	// Type of the stored data.
	Type enum.Type

	// FileName of the stored file.
	FileName string

	// User description of the stored data.
	Description string

	// Stored data checksum.
	Checksum string

	// Delete flag of the stored data.
	Deleted bool

	// Last update time of the stored data.
	UpdatedAt time.Time
}

// ClientEntry is the struct for the client side entry representation.
type ClientEntry struct {
	// Global ID of the entry.
	ID string

	// Global ID of the user.
	UserID string

	// Metadata
	Metadata
}

// ClientEntry is the struct for the server entry representation.
type ServerEntry struct {
	// Global entry ID.
	ID string

	// Global user ID.
	UserID string

	// Encrypted entry metadata.
	Metadata []byte
}

// User is the struct for the server side user representation.
type User struct {
	// Global user ID.
	ID string

	// User login.
	Login string

	// User password hash.
	PassHash string

	// Lock flag.
	Locked bool

	// Locking expiration time.
	LockedUntil time.Time
}
