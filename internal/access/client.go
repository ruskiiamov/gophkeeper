package access

import "github.com/ruskiiamov/gophkeeper/internal/dto"

type clientManager struct {

}

func NewClientManager(storage, client interface{}) *clientManager {
	//TODO
	return &clientManager{}
}

func (c * clientManager) Register(login, password string) error {
	//TODO
	return nil
}

func (c * clientManager) Login(login, password string) error {
	//TODO
	return nil
}

func (c *clientManager) GetCreds() (*dto.Creds, error) {
	//TODO
	return &dto.Creds{}, nil
}

func (c *clientManager) UpdatePass(creds *dto.Creds, newPassword string) (newKey string, err error) {
	//TODO
	return "", nil
}

