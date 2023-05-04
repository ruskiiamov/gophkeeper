package data

import "github.com/ruskiiamov/gophkeeper/internal/dto"

type clientKeeper struct {

}

func NewClientKeeper(cipher, storage, client interface{}) *clientKeeper {
	//TODO
	return &clientKeeper{}
}

func (c *clientKeeper) CheckSync(creds *dto.Creds) (bool, error) {
	//TODO
	return false, nil
}

func (c *clientKeeper) UpdateEncryption(creds *dto.Creds, newKey string) error {
	//TODO
	return nil
}

func (c *clientKeeper) AddLogPass(creds *dto.Creds, lp *dto.LogPass, description string) error {
	//TODO
	return nil
}

func (c *clientKeeper) AddText(creds *dto.Creds, text, description string) error {
	//TODO
	return nil
}

func (c *clientKeeper) AddFile(creds *dto.Creds, path, description string) error {
	//TODO
	return nil
}

func (c *clientKeeper) AddCard(creds *dto.Creds, card *dto.Card, description string) error {
	//TODO
	return nil
}

func (c *clientKeeper) Sync(creds *dto.Creds) error {
	//TODO
	return nil
}

func (c *clientKeeper) GetList(creds *dto.Creds) ([]*dto.Entry, error) {
	//TODO
	return []*dto.Entry{}, nil
}

func (c *clientKeeper) GetEntry(creds *dto.Creds, id string) (*dto.Entry, error) {
	//TODO
	return &dto.Entry{}, nil
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
