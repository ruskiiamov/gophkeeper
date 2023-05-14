package localstorage

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
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

func (s *storage) GetEntries(userID string) ([]*dto.ClientEntry, error) {
	//TODO
	return []*dto.ClientEntry{}, nil
}

func (s *storage) AddEntry(entry *dto.ClientEntry) error {
	//TODO
	return nil
}

func (s *storage) GetEntry(userID, id string) (*dto.ClientEntry, error) {
	//TODO
	return &dto.ClientEntry{}, nil
}

func (s *storage) AddOrUpdateEntry(entry *dto.ClientEntry) error {
	//TODO
	return nil
}
