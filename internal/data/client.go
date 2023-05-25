// Package data is the data management logic for the
// Gophkeeper client and server.
package data

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/enum"
	"golang.org/x/sync/errgroup"
)

const (
	chunkSize     = 64 * 1024
	tempSuffix    = "-temp"
	initialSuffix = "-initial"
)

type cipherBuilder interface {
	Make(key []byte) (Cipher, error)
}

// Cipher is the interface for the slice of bytes cipher.
type Cipher interface {
	Crypt(chunk []byte) []byte
}

type storage interface {
	GetEntries(ctx context.Context, userID string) ([]*dto.ClientEntry, error)
	AddEntry(ctx context.Context, entry *dto.ClientEntry) error
	GetEntry(ctx context.Context, userID, id string) (*dto.ClientEntry, error)
	AddOrUpdateEntry(ctx context.Context, entry *dto.ClientEntry) error
	UpdateChecksums(ctx context.Context, entries []*dto.ClientEntry) error
}

type provider interface {
	GetEntries(ctx context.Context, token string) ([]*dto.ServerEntry, error)
	AddEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error
	GetEntry(ctx context.Context, token, id string, dst io.Writer) (*dto.ServerEntry, error)
	UpdateEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error
}

type clientKeeper struct {
	filesPath string
	cipher    cipherBuilder
	storage   storage
	provider  provider
}

// NewClientKeeper returns the object with all methods necessary for the
// client side data management.
func NewClientKeeper(filesPath string, c cipherBuilder, s storage, p provider) *clientKeeper {
	return &clientKeeper{
		filesPath: filesPath,
		cipher:    c,
		storage:   s,
		provider:  p,
	}
}

// CheckSync check the existence of any not synced entries.
func (c *clientKeeper) CheckSync(ctx context.Context, creds *dto.Creds) (bool, error) {
	entries, err := c.getAllEntries(ctx, creds)
	if err != nil {
		return false, fmt.Errorf("get all entries error: %w", err)
	}

	for _, entry := range entries {
		if entry[0].Checksum != entry[1].Checksum {
			return false, nil
		}
	}

	return true, nil
}

// UpdateEncryption updates encryption for all local entries with the new cipher key.
func (c *clientKeeper) UpdateEncryption(ctx context.Context, creds *dto.Creds, newKey []byte) error {
	entries, err := c.storage.GetEntries(ctx, creds.UserID)
	if err != nil {
		return fmt.Errorf("storage get entries error: %w", err)
	}

	g, gCtx := errgroup.WithContext(ctx)
	checksums := make(map[string]chan string)

	defer c.removeFilesWithSuffix(creds.UserID, tempSuffix)

	for _, entry := range entries {
		entry := entry
		ch := make(chan string, 1)
		checksums[entry.ID] = ch

		g.Go(func() error {
			checksum, err := c.prepareNewEncryption(gCtx, entry, creds.Key, newKey)
			ch <- checksum
			return err
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("errgroup error: %w", err)
	}

	defer c.rollbackFiles(creds.UserID)

	g = new(errgroup.Group)
	for _, entry := range entries {
		entry := entry
		g.Go(func() error {
			path := filepath.Join(c.filesPath, entry.UserID, entry.ID)
			initialPath := filepath.Join(c.filesPath, entry.UserID, entry.ID+initialSuffix)
			return os.Rename(path, initialPath)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("errgroup error: %w", err)
	}

	g = new(errgroup.Group)
	for _, entry := range entries {
		entry := entry
		g.Go(func() error {
			tempPath := filepath.Join(c.filesPath, entry.UserID, entry.ID+tempSuffix)
			path := filepath.Join(c.filesPath, entry.UserID, entry.ID)
			return os.Rename(tempPath, path)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("errgroup error: %w", err)
	}

	for _, entry := range entries {
		entry.Checksum = <-checksums[entry.ID]
	}

	err = c.storage.UpdateChecksums(ctx, entries)
	if err != nil {
		return fmt.Errorf("storage update checksums error: %w", err)
	}

	c.removeFilesWithSuffix(creds.UserID, initialSuffix)

	return nil
}

// AddLogPass adds new encrypted login-password data to the local storage.
func (c *clientKeeper) AddLogPass(ctx context.Context, creds *dto.Creds, lp *dto.LogPass, description string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("uuid generation error: %w", err)
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(lp); err != nil {
		return fmt.Errorf("gob encoding error: %w", err)
	}

	checksum, err := c.addData(ctx, creds, &buffer, id.String())
	if err != nil {
		return fmt.Errorf("add data error: %w", err)
	}

	entry := &dto.ClientEntry{
		ID:     id.String(),
		UserID: creds.UserID,
		Metadata: dto.Metadata{
			Type:        enum.LogPass,
			Description: description,
			Checksum:    checksum,
			UpdatedAt:   time.Now(),
		},
	}

	if err := c.storage.AddEntry(ctx, entry); err != nil {
		c.deleteData(creds, id.String())
		return fmt.Errorf("storage add entry error: %w", err)
	}

	return nil
}

// AddText adds new encrypted text data to the local storage.
func (c *clientKeeper) AddText(ctx context.Context, creds *dto.Creds, text, description string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("uuid generation error: %w", err)
	}

	reader := bytes.NewReader([]byte(text))

	checksum, err := c.addData(ctx, creds, reader, id.String())
	if err != nil {
		return fmt.Errorf("add data error: %w", err)
	}

	entry := &dto.ClientEntry{
		ID:     id.String(),
		UserID: creds.UserID,
		Metadata: dto.Metadata{
			Type:        enum.Text,
			Description: description,
			Checksum:    checksum,
			UpdatedAt:   time.Now(),
		},
	}

	if err := c.storage.AddEntry(ctx, entry); err != nil {
		c.deleteData(creds, id.String())
		return fmt.Errorf("storage add entry error: %w", err)
	}

	return nil
}

// AddFile adds new encrypted file to the local storage.
func (c *clientKeeper) AddFile(ctx context.Context, creds *dto.Creds, path, description string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("uuid generation error: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	checksum, err := c.addData(ctx, creds, file, id.String())
	if err != nil {
		return fmt.Errorf("add data error: %w", err)
	}

	entry := &dto.ClientEntry{
		ID:     id.String(),
		UserID: creds.UserID,
		Metadata: dto.Metadata{
			Type:        enum.File,
			FileName:    filepath.Base(path),
			Description: description,
			Checksum:    checksum,
			UpdatedAt:   time.Now(),
		},
	}

	if err := c.storage.AddEntry(ctx, entry); err != nil {
		c.deleteData(creds, id.String())
		return fmt.Errorf("storage add entry error: %w", err)
	}

	return nil
}

// AddCard adds new encrypted bank card data to the local storage.
func (c *clientKeeper) AddCard(ctx context.Context, creds *dto.Creds, card *dto.Card, description string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("uuid generation error: %w", err)
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(card); err != nil {
		return fmt.Errorf("gob encoding error: %w", err)
	}

	checksum, err := c.addData(ctx, creds, &buffer, id.String())
	if err != nil {
		return fmt.Errorf("add data error: %w", err)
	}

	entry := &dto.ClientEntry{
		ID:     id.String(),
		UserID: creds.UserID,
		Metadata: dto.Metadata{
			Type:        enum.Card,
			Description: description,
			Checksum:    checksum,
			UpdatedAt:   time.Now(),
		},
	}

	if err := c.storage.AddEntry(ctx, entry); err != nil {
		c.deleteData(creds, id.String())
		return fmt.Errorf("storage add entry error: %w", err)
	}

	return nil
}

// Sync makes data synchronization between client and server sides.
func (c *clientKeeper) Sync(ctx context.Context, creds *dto.Creds) error {
	entries, err := c.getAllEntries(ctx, creds)
	if err != nil {
		return fmt.Errorf("get all entries error: %w", err)
	}

	var wg sync.WaitGroup
	errs := make(map[string]chan error)

	for id, entry := range entries {
		if entry[0] != nil && entry[1] != nil && entry[0].Checksum == entry[1].Checksum {
			continue
		}

		wg.Add(1)
		ch := make(chan error, 1)
		errs[id] = ch

		if entry[0] == nil {
			go func(id string, ch chan<- error) {
				ch <- c.upload(ctx, creds, id)
				wg.Done()
			}(id, ch)
			continue
		}

		if entry[1] == nil || (entry[0].Checksum != entry[1].Checksum && entry[0].UpdatedAt.After(entry[1].UpdatedAt)) {
			go func(id string, ch chan<- error) {
				ch <- c.download(ctx, creds, id)
				wg.Done()
			}(id, ch)
			continue
		}

		if entry[0].Checksum != entry[1].Checksum && entry[0].UpdatedAt.Before(entry[1].UpdatedAt) {
			go func(id string, ch chan<- error) {
				ch <- c.update(ctx, creds, id)
				wg.Done()
			}(id, ch)
			continue
		}
	}

	wg.Wait()

	var sb strings.Builder
	for id, chErr := range errs {
		err = <-chErr
		if err != nil {
			sb.WriteString(fmt.Sprintf("\n%s sync error: %s\n", id, err))
		}
	}
	if joinedErrStr := sb.String(); joinedErrStr != "" {
		return errors.New(joinedErrStr)
	}

	return nil
}

// GetList returns list of entries metadata from the local DB.
func (c *clientKeeper) GetList(ctx context.Context, creds *dto.Creds) ([]*dto.ClientEntry, error) {
	list, err := c.storage.GetEntries(ctx, creds.UserID)
	if err != nil {
		return nil, fmt.Errorf("storage get entries error: %w", err)
	}

	return list, nil
}

// GetEntry returns entry metadata from the local DB.
func (c *clientKeeper) GetEntry(ctx context.Context, creds *dto.Creds, id string) (*dto.ClientEntry, error) {
	entry, err := c.storage.GetEntry(ctx, creds.UserID, id)
	if err != nil {
		return nil, fmt.Errorf("storage get entry error: %w", err)
	}

	return entry, nil
}

// GetLogPass returns the decrypted login-password data from the local storage.
func (c *clientKeeper) GetLogPass(ctx context.Context, creds *dto.Creds, id string) (*dto.LogPass, error) {
	var buffer bytes.Buffer
	err := c.getData(ctx, creds, id, &buffer)
	if err != nil {
		return nil, fmt.Errorf("get data error: %w", err)
	}

	logPass := new(dto.LogPass)

	if err := gob.NewDecoder(&buffer).Decode(logPass); err != nil {
		return nil, fmt.Errorf("gob decode error: %w", err)
	}

	return logPass, nil
}

// GetText returns the decrypted text data from the local storage.
func (c *clientKeeper) GetText(ctx context.Context, creds *dto.Creds, id string) (string, error) {
	var buffer bytes.Buffer
	err := c.getData(ctx, creds, id, &buffer)
	if err != nil {
		return "", fmt.Errorf("get data error: %w", err)
	}

	return buffer.String(), nil
}

// GetFile returns the decrypted file from the local storage.
func (c *clientKeeper) GetFile(ctx context.Context, creds *dto.Creds, id string) (string, error) {
	entry, err := c.storage.GetEntry(ctx, creds.UserID, id)
	if err != nil {
		return "", fmt.Errorf("storage get entry error: %w", err)
	}

	file, err := os.OpenFile(entry.FileName, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0777)
	if err != nil {
		return "", fmt.Errorf("open file error: %w", err)
	}

	remove := true
	defer func() {
		if remove {
			os.Remove(entry.FileName)
		}
	}()
	defer file.Close()

	err = c.getData(ctx, creds, id, file)
	if err != nil {
		return "", fmt.Errorf("get data error: %w", err)
	}

	path, err := filepath.Abs(file.Name())
	if err != nil {
		return "", fmt.Errorf("filepath error: %w", err)
	}

	remove = false

	return path, nil
}

// GetCard returns the decrypted bank card data from the local storage.
func (c *clientKeeper) GetCard(ctx context.Context, creds *dto.Creds, id string) (*dto.Card, error) {
	var buffer bytes.Buffer
	err := c.getData(ctx, creds, id, &buffer)
	if err != nil {
		return nil, fmt.Errorf("get data error: %w", err)
	}

	card := new(dto.Card)

	if err := gob.NewDecoder(&buffer).Decode(card); err != nil {
		return nil, fmt.Errorf("gob decode error: %w", err)
	}

	return card, nil
}

func (c *clientKeeper) getAllEntries(ctx context.Context, creds *dto.Creds) (map[string][2]*dto.ClientEntry, error) {
	g, ctx := errgroup.WithContext(ctx)

	serverEntries := make(chan []*dto.ClientEntry, 1)
	g.Go(func() error {
		entries, err := c.provider.GetEntries(ctx, creds.Token)
		if err != nil {
			return fmt.Errorf("provider get entries error: %w", err)
		}

		clientEntries := make([]*dto.ClientEntry, 0, len(entries))
		for _, entry := range entries {
			cipher, err := c.cipher.Make(creds.Key)
			if err != nil {
				return fmt.Errorf("cipher make error: %w", err)
			}

			decryptedMetadata := cipher.Crypt(entry.Metadata)
			reader := bytes.NewReader(decryptedMetadata)

			metadata := new(dto.Metadata)
			err = gob.NewDecoder(reader).Decode(metadata)
			if err != nil {
				return fmt.Errorf("gob decoding error: %w", err)
			}

			clientEntries = append(clientEntries, &dto.ClientEntry{
				ID:       entry.ID,
				UserID:   entry.UserID,
				Metadata: *metadata,
			})
		}

		serverEntries <- clientEntries

		return nil
	})

	localEntries := make(chan []*dto.ClientEntry, 1)
	g.Go(func() error {
		entries, err := c.storage.GetEntries(ctx, creds.UserID)
		if err != nil {
			return fmt.Errorf("storage get entries error: %w", err)
		}
		localEntries <- entries

		return nil
	})

	err := g.Wait()
	if err != nil {
		return nil, fmt.Errorf("get entries error: %w", err)
	}

	m := make(map[string][2]*dto.ClientEntry)
	for _, item := range <-serverEntries {
		m[item.ID] = [2]*dto.ClientEntry{0: item}
	}
	for _, item := range <-localEntries {
		if element, ok := m[item.ID]; ok {
			element[1] = item
			m[item.ID] = element
		} else {
			m[item.ID] = [2]*dto.ClientEntry{1: item}
		}
	}

	return m, nil
}

func (c *clientKeeper) addData(ctx context.Context, creds *dto.Creds, src io.Reader, id string) (string, error) {
	if err := c.checkOrCreateUserDir(creds.UserID); err != nil {
		return "", fmt.Errorf("check or create user dir error: %w", err)
	}

	tempPath := filepath.Join(c.filesPath, creds.UserID, id+tempSuffix)
	defer os.Remove(tempPath)

	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0777)
	if err != nil {
		return "", fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	h := md5.New()

	cipher, err := c.cipher.Make(creds.Key)
	if err != nil {
		return "", fmt.Errorf("cipher make error: %s", err)
	}

	chunk := make([]byte, chunkSize)
	var encryptedChunk []byte
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context done")
		default:
		}

		n, err := src.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		encryptedChunk = cipher.Crypt(chunk)

		_, err = h.Write(encryptedChunk)
		if err != nil {
			return "", fmt.Errorf("hash write error: %w", err)
		}

		_, err = file.Write(encryptedChunk)
		if err != nil {
			return "", fmt.Errorf("file write error: %w", err)
		}
	}

	checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))

	path := filepath.Join(c.filesPath, creds.UserID, id)
	if err := os.Rename(tempPath, path); err != nil {
		return "", fmt.Errorf("file rename error: %w", err)
	}

	return checksum, nil
}

func (c *clientKeeper) deleteData(creds *dto.Creds, id string) error {
	path := filepath.Join(c.filesPath, creds.UserID, id)
	err := os.Remove(path)
	if err != nil {
		return fmt.Errorf("remove file error: %w", err)
	}

	return nil
}

func (c *clientKeeper) getData(ctx context.Context, creds *dto.Creds, id string, dst io.Writer) error {
	path := filepath.Join(c.filesPath, creds.UserID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	cipher, err := c.cipher.Make(creds.Key)
	if err != nil {
		return fmt.Errorf("cipher make error: %w", err)
	}

	chunk := make([]byte, chunkSize)
	var decryptedChunk []byte
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done")
		default:
		}

		n, err := file.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		decryptedChunk = cipher.Crypt(chunk)

		_, err = dst.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("dst write error: %w", err)
		}
	}

	return nil
}

func (c *clientKeeper) upload(ctx context.Context, creds *dto.Creds, id string) error {
	entry, err := c.storage.GetEntry(ctx, creds.UserID, id)
	if err != nil {
		return fmt.Errorf("storage get entry error: %w", err)
	}

	path := filepath.Join(c.filesPath, creds.UserID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	cipher, err := c.cipher.Make(creds.Key)
	if err != nil {
		return fmt.Errorf("cipher make error: %w", err)
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(entry.Metadata); err != nil {
		return fmt.Errorf("fob encoding error: %w", err)
	}
	encryptedMetadata := cipher.Crypt(buffer.Bytes())

	serverEntry := &dto.ServerEntry{
		ID:       id,
		UserID:   creds.UserID,
		Metadata: encryptedMetadata,
	}

	if err := c.provider.AddEntry(ctx, creds.Token, serverEntry, file); err != nil {
		return fmt.Errorf("provider add entry error: %w", err)
	}

	return nil
}

func (c *clientKeeper) download(ctx context.Context, creds *dto.Creds, id string) error {
	if err := c.checkOrCreateUserDir(creds.UserID); err != nil {
		return fmt.Errorf("check or create user dir error: %w", err)
	}

	tempPath := filepath.Join(c.filesPath, creds.UserID, id+tempSuffix)
	defer os.Remove(tempPath)

	file, err := os.OpenFile(tempPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	cipher, err := c.cipher.Make(creds.Key)
	if err != nil {
		return fmt.Errorf("cipher make error: %w", err)
	}

	serverEntry, err := c.provider.GetEntry(ctx, creds.Token, id, file)
	if err != nil {
		return fmt.Errorf("provider get entry error: %w", err)
	}

	metadata := cipher.Crypt(serverEntry.Metadata)
	buffer := bytes.NewBuffer(metadata)

	entry := &dto.ClientEntry{ID: id, UserID: creds.UserID}

	if err := gob.NewDecoder(buffer).Decode(&(entry.Metadata)); err != nil {
		return fmt.Errorf("gob decoding error: %w", err)
	}

	if err := c.storage.AddOrUpdateEntry(ctx, entry); err != nil {
		return fmt.Errorf("storage add or update error: %w", err)
	}

	path := filepath.Join(c.filesPath, creds.UserID, id)
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("file rename error: %w", err)
	}

	return nil
}

func (c *clientKeeper) update(ctx context.Context, creds *dto.Creds, id string) error {
	entry, err := c.storage.GetEntry(ctx, creds.UserID, id)
	if err != nil {
		return fmt.Errorf("storage get entry error: %w", err)
	}

	path := filepath.Join(c.filesPath, creds.UserID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	cipher, err := c.cipher.Make(creds.Key)
	if err != nil {
		return fmt.Errorf("cipher make error: %w", err)
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(entry.Metadata); err != nil {
		return fmt.Errorf("gob encoding error: %w", err)
	}
	encryptedMetadata := cipher.Crypt(buffer.Bytes())

	serverEntry := &dto.ServerEntry{
		ID:       id,
		UserID:   creds.UserID,
		Metadata: encryptedMetadata,
	}

	if err := c.provider.UpdateEntry(ctx, creds.Token, serverEntry, file); err != nil {
		return fmt.Errorf("provider update entry error: %w", err)
	}

	return nil
}

func (c *clientKeeper) prepareNewEncryption(ctx context.Context, entry *dto.ClientEntry, oldKey, newKey []byte) (string, error) {
	path := filepath.Join(c.filesPath, entry.UserID, entry.ID)
	file, err := os.OpenFile(path, os.O_RDONLY, 0777)
	if err != nil {
		return "", fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	tempPath := filepath.Join(c.filesPath, entry.UserID, entry.ID+tempSuffix)
	tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0777)
	if err != nil {
		return "", fmt.Errorf("open temp file error: %w", err)
	}
	defer tempFile.Close()

	h := md5.New()

	oldCipher, err := c.cipher.Make(oldKey)
	if err != nil {
		return "", fmt.Errorf("cipher make error: %w", err)
	}

	newCipher, err := c.cipher.Make(newKey)
	if err != nil {
		return "", fmt.Errorf("cipher make error: %w", err)
	}

	chunk := make([]byte, chunkSize)
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context done")
		default:
		}

		n, err := file.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		decryptedChunk := oldCipher.Crypt(chunk)
		encryptedChunk := newCipher.Crypt(decryptedChunk)

		_, err = h.Write(encryptedChunk)
		if err != nil {
			return "", fmt.Errorf("hash write error: %w", err)
		}

		_, err = tempFile.Write(encryptedChunk)
		if err != nil {
			return "", fmt.Errorf("file write error: %w", err)
		}
	}

	checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return checksum, nil
}

func (c *clientKeeper) checkOrCreateUserDir(userID string) error {
	dirPath := filepath.Join(c.filesPath, userID)

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, 0777)
		if err != nil {
			return fmt.Errorf("dir creation error: %w", err)
		}
	}

	return nil
}

func (c *clientKeeper) removeFilesWithSuffix(userID, suffix string) error {
	dirPath := filepath.Join(c.filesPath, userID)
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("open dir error: %w", err)
	}
	defer dir.Close()

	files, err := dir.ReadDir(0)
	if err != nil {
		return fmt.Errorf("read dir error: %w", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), suffix) {
			path := filepath.Join(c.filesPath, userID, file.Name())
			os.Remove(path)
		}
	}

	return nil
}

func (c *clientKeeper) rollbackFiles(userID string) error {
	dirPath := filepath.Join(c.filesPath, userID)
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("open dir error: %w", err)
	}
	defer dir.Close()

	files, err := dir.ReadDir(0)
	if err != nil {
		return fmt.Errorf("read dir error: %w", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), initialSuffix) {
			initPath := filepath.Join(c.filesPath, userID, file.Name())
			path := filepath.Join(c.filesPath, userID, strings.TrimSuffix(file.Name(), initialSuffix))
			os.Rename(initPath, path)
		}
	}

	return nil
}
