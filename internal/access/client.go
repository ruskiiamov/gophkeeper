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

func (c * clientManager) Login(login, password string) (credsNotChanged bool, err error) {
	//TODO
	return false, nil
}

func (c *clientManager) GetCreds() (*dto.Creds, error) {
	//TODO
	return &dto.Creds{}, nil
}

func (c *clientManager) GetCredsByLogin(login string) (*dto.Creds, error) {
	//TODO
	return &dto.Creds{}, nil
}

func (c *clientManager) GetKey(password string) (string, error) {
	//TODO
	return "", nil
}

func (c *clientManager) UpdateCreds(login, password string) error {
	//TODO
	return nil
}

func (c *clientManager) UpdatePass(creds *dto.Creds, oldPassword, newPassword string) error {
	//TODO
	return nil
}

func (c *clientManager) Logout(creds *dto.Creds) error {
	//TODO
	return nil
}

