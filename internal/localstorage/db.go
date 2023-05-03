package localstorage

import (
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
)

type storage struct {
	conn *sql.DB
}

func New(dsn string) (*storage, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	return &storage{conn: db}, nil
}

func (s *storage) Close() {
	s.conn.Close()
}