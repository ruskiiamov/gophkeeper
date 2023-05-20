package dto

import (
	"time"

	"github.com/ruskiiamov/gophkeeper/internal/enum"
)

type Creds struct {
	UserID string
	Key    []byte
	Token  string
}

type LogPass struct {
	Login    string
	Password string
}

type Card struct {
	Number string
	Owner  string
	Expire string
	Code   string
	Pin    string
}

type Metadata struct {
	Type        enum.Type
	FileName    string
	Description string
	Checksum    string
	Deleted     bool
	UpdatedAt   time.Time
}

type ClientEntry struct {
	ID     string
	UserID string
	Metadata
}

type ServerEntry struct {
	ID       string
	UserID   string
	Metadata []byte
}

type User struct {
	ID          string
	Login       string
	PassHash    string
	Locked      bool
	LockedUntil time.Time
}
