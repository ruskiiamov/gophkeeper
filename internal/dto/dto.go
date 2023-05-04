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

type Entry struct {
	ID string
	Type enum.Type
	Description string
	UpdatedAt time.Time
}
