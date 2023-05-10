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

const chunkSize = 64 * 1024

type cipher interface {
	Init(key string) error
	Encrypt(chunk []byte) ([]byte, error)
	Decrypt(chunk []byte) ([]byte, error)
}

type storage interface {
	GetEntries(userID string) ([]*dto.Entry, error)
	AddEntry(entry *dto.Entry) error
	GetEntry(userID, id string) (*dto.Entry, error)
	AddOrUpdateEntry(entry *dto.Entry) error
}

type provider interface {
	GetEntries(token string) ([]*dto.Entry, error)
	AddEntry(token, id string, encryptedMetadata []byte, src io.Reader) error
	GetEntry(token, id string, dst io.Writer) (encryptedMetadata []byte, err error)
	UpdateEntry(token, id string, encryptedMetadata []byte, src io.Reader) error
}

type clientKeeper struct {
	filesPath string
	cipher    cipher
	storage   storage
	provider  provider
}

func NewClientKeeper(filesPath string, c cipher, s storage, p provider) *clientKeeper {
	return &clientKeeper{
		filesPath: filesPath,
		cipher:    c,
		storage:   s,
		provider:  p,
	}
}

func (c *clientKeeper) CheckSync(creds *dto.Creds) (bool, error) {
	entries, err := c.getAllEntries(creds)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if entry[0].Checksum != entry[1].Checksum {
			return false, nil
		}
	}

	return true, nil
}

func (c *clientKeeper) UpdateEncryption(creds *dto.Creds, newKey string) error {
	entries, err := c.storage.GetEntries(creds.UserID)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(context.TODO())

	for _, entry := range entries {
		entry := entry
		g.Go(func() error {
			return c.updateEntryEncryption(ctx, entry, creds.Key, newKey)
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) AddLogPass(creds *dto.Creds, lp *dto.LogPass, description string) error {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(lp); err != nil {
		return err
	}

	if err := c.addEntry(creds, enum.LogPass, &buffer, description); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) AddText(creds *dto.Creds, text, description string) error {
	reader := bytes.NewReader([]byte(text))

	if err := c.addEntry(creds, enum.Text, reader, description); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) AddFile(creds *dto.Creds, path, description string) error {
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := c.addEntry(creds, enum.File, file, description); err != nil {
		return nil
	}

	return nil
}

func (c *clientKeeper) AddCard(creds *dto.Creds, card *dto.Card, description string) error {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(card); err != nil {
		return err
	}

	if err := c.addEntry(creds, enum.Card, &buffer, description); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) Sync(creds *dto.Creds) error {
	entries, err := c.getAllEntries(creds)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errs := make(map[string]chan error)

	for id, entry := range entries {
		if entry[0].Checksum == entry[1].Checksum {
			continue
		}

		wg.Add(1)
		ch := make(chan error, 1)
		errs[id] = ch

		if entry[0] == nil {
			go func(id string, ch chan<- error) {
				ch <- c.upload(creds.Token, creds.UserID, id)
				wg.Done()
			}(id, ch)
			continue
		}

		if entry[1] == nil || (entry[0].Checksum != entry[1].Checksum && entry[0].UpdatedAt.After(entry[1].UpdatedAt)) {
			go func(id string, ch chan<- error) {
				ch <- c.download(creds.Token, creds.UserID, id)
				wg.Done()
			}(id, ch)
			continue
		}

		if entry[0].Checksum != entry[1].Checksum && entry[0].UpdatedAt.Before(entry[1].UpdatedAt) {
			go func(id string, ch chan<- error) {
				ch <- c.update(creds.Token, creds.UserID, id)
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
			sb.WriteString(fmt.Sprintf("%s sync error: %s\n", id, err))
		}
	}
	if joinedErrStr := sb.String(); joinedErrStr != "" {
		return errors.New(joinedErrStr)
	}

	return nil
}

func (c *clientKeeper) GetList(creds *dto.Creds) ([]*dto.Entry, error) {
	list, err := c.storage.GetEntries(creds.UserID)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (c *clientKeeper) GetEntry(creds *dto.Creds, id string) (*dto.Entry, error) {
	entry, err := c.storage.GetEntry(creds.UserID, id)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (c *clientKeeper) GetLogPass(creds *dto.Creds, id string) (*dto.LogPass, error) {
	//TODO
	return &dto.LogPass{}, nil
}

func (c *clientKeeper) GetText(creds *dto.Creds, id string) (string, error) {
	//TODO
	return "", nil
}

func (c *clientKeeper) GetFile(creds *dto.Creds, id string) (string, error) {
	//TODO
	return "", nil
}

func (c *clientKeeper) GetCard(creds *dto.Creds, id string) (*dto.Card, error) {
	//TODO
	return &dto.Card{}, nil
}

func (c *clientKeeper) getAllEntries(creds *dto.Creds) (map[string][2]*dto.Entry, error) {
	//TODO add async call
	serverEntries, err := c.provider.GetEntries(creds.Token)
	if err != nil {
		return nil, err
	}

	//TODO add async call
	localEntries, err := c.storage.GetEntries(creds.UserID)
	if err != nil {
		return nil, err
	}

	m := make(map[string][2]*dto.Entry)
	for _, item := range serverEntries {
		m[item.ID] = [2]*dto.Entry{0: item}
	}
	for _, item := range localEntries {
		if element, ok := m[item.ID]; ok {
			element[1] = item
			m[item.ID] = element
		} else {
			m[item.ID] = [2]*dto.Entry{1: item}
		}
	}

	return m, nil
}

func (c *clientKeeper) addEntry(creds *dto.Creds, t enum.Type, src io.Reader, description string) error {
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}

	path := filepath.Join(c.filesPath, creds.UserID, id.String())
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	h := md5.New()

	err = c.cipher.Init(creds.Key) //TODO ???
	if err != nil {
		return err
	}

	chunk := make([]byte, 0, chunkSize)
	var encryptedChunk []byte
	for {
		n, err := src.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		encryptedChunk, err = c.cipher.Encrypt(chunk) //TODO ???
		if err != nil {
			return err
		}

		h.Write(encryptedChunk)
		file.Write(encryptedChunk)
	}

	checksum := base64.StdEncoding.EncodeToString(h.Sum(nil))

	entry := &dto.Entry{
		ID:     id.String(),
		UserID: creds.UserID,
		Metadata: dto.Metadata{
			Type:        t,
			Description: description,
			Checksum:    checksum,
			UpdatedAt:   time.Now(),
		},
	}

	if err := c.storage.AddEntry(entry); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) upload(token, userID, id string) error {
	entry, err := c.storage.GetEntry(userID, id)
	if err != nil {
		return err
	}

	path := filepath.Join(c.filesPath, userID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}
	defer file.Close()

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(entry.Metadata); err != nil {
		return err
	}
	encryptedMetadata, err := c.cipher.Encrypt(buffer.Bytes())
	if err != nil {
		return err
	}

	if err := c.provider.AddEntry(token, id, encryptedMetadata, file); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) download(token, userID, id string) error {
	path := filepath.Join(c.filesPath, userID, id)
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil
	}
	defer file.Close()

	encryptedMetadata, err := c.provider.GetEntry(token, id, file)
	if err != nil {
		return err
	}

	metadata, err := c.cipher.Decrypt(encryptedMetadata)
	if err != nil {
		//TODO rollback ???
		return err
	}
	buffer := bytes.NewBuffer(metadata)

	entry := &dto.Entry{ID: id, UserID: userID}

	if err := gob.NewDecoder(buffer).Decode(&(entry.Metadata)); err != nil {
		//TODO rollback ???
		return err
	}

	if err := c.storage.AddOrUpdateEntry(entry); err != nil {
		//TODO rollback ???
		return err
	}

	return nil
}

func (c *clientKeeper) update(token, userID, id string) error {
	entry, err := c.storage.GetEntry(userID, id)
	if err != nil {
		return err
	}

	path := filepath.Join(c.filesPath, userID, id)
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}
	defer file.Close()

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(entry.Metadata); err != nil {
		return err
	}
	encryptedMetadata, err := c.cipher.Encrypt(buffer.Bytes())
	if err != nil {
		return err
	}

	if err := c.provider.UpdateEntry(token, id, encryptedMetadata, file); err != nil {
		return err
	}

	return nil
}

func (c *clientKeeper) updateEntryEncryption(ctx context.Context, entry *dto.Entry, oldKey, newKey string) error {
	//TODO
	return nil
}
