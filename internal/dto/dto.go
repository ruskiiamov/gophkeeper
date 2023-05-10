package dto

import (
	"time"

	"github.com/ruskiiamov/gophkeeper/internal/enum"
)

type Creds struct {
	UserID string
	Key    string
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
	Description string
	Checksum    string
	Deleted     bool
	UpdatedAt   time.Time
}

type Entry struct {
	ID     string
	UserID string
	Metadata
}
