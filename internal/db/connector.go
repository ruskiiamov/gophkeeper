package db

import (
	"context"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
)

type connector struct {

}

func NewConnector(dsn string) (*connector, error) {
	return &connector{}, nil
}

func (c *connector) Close() {

}

func (c *connector) AddUser(ctx context.Context, login, passHash string) (id string, err error) {
	//TODO
	return "", nil
}

func (c *connector) GetUser(ctx context.Context, login string) (*dto.User, error) {
	//TODO
	return nil, nil
}

func (c *connector) GetAndUpdatePassHash(ctx context.Context, userID string, passHashCh chan<- string, lockedPassHashCh <-chan string, errCh chan<- error) {
	//TODO
}

func (c *connector) UpdatePassHash(ctx context.Context, userID, passHash string) error {
	//TODO
	return nil
}
