// Package file is the local file storage implementation.
package file

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
)

const (
	tempSuffix = "-temp"
	chunkSize  = 64 * 1024
)

type storage struct {
	filesPath string
}

// NewStorage returns the object that has all necessary methods for 
// Gophkeeper files management. 
func NewStorage(filesPath string) *storage {
	return &storage{filesPath: filesPath}
}

// Delete removes file from the storage.
func (s *storage) Delete(ctx context.Context, id, userID string) error {
	path := filepath.Join(s.filesPath, userID, id)

	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("file remove error: %w", err)
	}

	return nil
}

// Add makes adding of the file to the storage by chunks.
func (s *storage) Add(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte) error {
	dirPath := filepath.Join(s.filesPath, entry.UserID)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, 0777)
		if err != nil {
			return fmt.Errorf("mkdir error: %w", err)
		}
	}

	tempPath := filepath.Join(s.filesPath, entry.UserID, entry.ID+tempSuffix)
	defer os.Remove(tempPath)

	file, err := os.OpenFile(tempPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	var chunk []byte
	var ok bool
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done")
		default:
		}

		chunk, ok = <-chunkCh
		if !ok {
			break
		}

		_, err = file.Write(chunk)
		if err != nil {
			return fmt.Errorf("file write error: %w", err)
		}
	}

	path := filepath.Join(s.filesPath, entry.UserID, entry.ID)
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("file rename error: %w", err)
	}

	return nil
}

// Add makes getting of the file from the storage by chunks.
func (s *storage) Get(ctx context.Context, id, userID string, chunkCh chan<- []byte) error {
	path := filepath.Join(s.filesPath, userID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done")
		default:
		}

		chunk := make([]byte, chunkSize)
		n, err := file.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		chunkCh <- chunk
	}

	close(chunkCh)

	return nil
}
