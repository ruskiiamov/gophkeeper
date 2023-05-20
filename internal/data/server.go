package data

import (
	"context"
	"fmt"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"golang.org/x/sync/errgroup"
)

type serverKeeper struct {
	db dbConnector
	fs fileStorage
}

type dbConnector interface {
	CheckAndLockEntry(ctx context.Context, id, userID string) error
	CheckAndLockEntries(ctx context.Context, userID string) error
	UnlockEntry(ctx context.Context, id, userID string) error
	UnlockEntries(ctx context.Context, userID string) error
	GetEntries(ctx context.Context, userID string) ([]*dto.ServerEntry, error)
	ForceDeleteEntry(ctx context.Context, id, userID string) error
	AddEntry(ctx context.Context, entry *dto.ServerEntry) error
	GetEntry(ctx context.Context, id, userID string) (*dto.ServerEntry, error)
	UpdateEntry(ctx context.Context, entry *dto.ServerEntry) error
}

type fileStorage interface {
	Delete(ctx context.Context, id, userID string) error
	Add(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte) error
	Get(ctx context.Context, id, userID string, chunkCh chan<- []byte) error
}

func NewServerKeeper(db dbConnector, fs fileStorage) *serverKeeper {
	return &serverKeeper{
		db: db,
		fs: fs,
	}
}

func (s *serverKeeper) CheckAndLockEntry(ctx context.Context, id, userID string) error {
	return s.db.CheckAndLockEntry(ctx, id, userID)
}

func (s *serverKeeper) CheckAndLockEntries(ctx context.Context, userID string) error {
	return s.db.CheckAndLockEntries(ctx, userID)
}

func (s *serverKeeper) UnlockEntries(ctx context.Context, userID string) error {
	return s.db.UnlockEntries(ctx, userID)
}

func (s *serverKeeper) UnlockEntry(ctx context.Context, id, userID string) error {
	return s.db.UnlockEntry(ctx, id, userID)
}

func (s *serverKeeper) ForceDeleteEntries(ctx context.Context, userID string) error {
	entries, err := s.db.GetEntries(ctx, userID)
	if err != nil {
		return fmt.Errorf("db get entries error: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	for _, entry := range entries {
		entry := entry
		g.Go(func() error {
			err := s.fs.Delete(ctx, entry.ID, userID)
			if err != nil {
				return fmt.Errorf("file delete error: %w", err)
			}
			err = s.db.ForceDeleteEntry(ctx, entry.ID, userID)
			if err != nil {
				return fmt.Errorf("db force delete entry error: %w", err)
			}

			return nil
		})
	}

	return g.Wait()
}

func (s *serverKeeper) GetEntries(ctx context.Context, userID string) ([]*dto.ServerEntry, error) {
	entries, err := s.db.GetEntries(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("db get entries error: %w", err)
	}

	return entries, nil
}

func (s *serverKeeper) AddEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error) {
	err := s.fs.Add(ctx, entry, chunkCh)
	if err != nil {
		errCh <- fmt.Errorf("file add error: %w", err)
		return
	}

	err = s.db.AddEntry(ctx, entry)
	if err != nil {
		errCh <- fmt.Errorf("db add entry error: %w", err)
		return
	}

	close(errCh)
}

func (s *serverKeeper) GetEntry(ctx context.Context, id, userID string, metadataCh chan<- *dto.ServerEntry, chunkCh chan<- []byte, errCh chan<- error) {

	entry, err := s.db.GetEntry(ctx, id, userID)
	if err != nil {
		errCh <- fmt.Errorf("db get entry error: %w", err)
		return
	}

	metadataCh <- entry

	err = s.fs.Get(ctx, id, userID, chunkCh)
	if err != nil {
		errCh <- fmt.Errorf("file get error: %w", err)
		return
	}

	close(errCh)
}

func (s *serverKeeper) UpdateEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error) {
	err := s.fs.Add(ctx, entry, chunkCh)
	if err != nil {
		errCh <- fmt.Errorf("file add error: %w", err)
		return
	}

	err = s.db.UpdateEntry(ctx, entry)
	if err != nil {
		errCh <- fmt.Errorf("db update entry error: %w", err)
		return
	}

	close(errCh)
}
