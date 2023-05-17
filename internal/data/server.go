package data

import (
	"context"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
)

type serverKeeper struct {

}

type dbConnector interface {

}

type fileStorage interface {

}

func NewServerKeeper(db dbConnector, fs fileStorage) *serverKeeper {
	return &serverKeeper{}
}

func (s *serverKeeper) CheckAndLockEntry(ctx context.Context, id, userID string) error {
	//TODO
	return nil
}

func (s *serverKeeper) CheckAndLockEntries(ctx context.Context, userID string) error {
	//TODO
	return nil
}

func (s *serverKeeper) UnlockEntries(ctx context.Context, userID string) error {
	//TODO
	return nil
}

func (s *serverKeeper) UnlockEntry(ctx context.Context, id, userID string) error {
	//TODO
	return nil
}

func (s *serverKeeper) ForceDeleteEntries(ctx context.Context, userID string) error {
	//TODO
	return nil
}

func (s *serverKeeper) GetEntries(ctx context.Context, userID string) ([]*dto.ServerEntry, error) {
	//TODO
	return nil, nil
}

func (s *serverKeeper) AddEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error) {
	//TODO
}

func (s *serverKeeper) GetEntry(ctx context.Context, id, userID string, metadataCh chan<- *dto.ServerEntry, chunkCh chan<- []byte , errCh chan<- error) {
	//TODO
}

func (s *serverKeeper) UpdateEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error) {
	//TODO
}
