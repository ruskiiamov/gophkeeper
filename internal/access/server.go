package access

import "context"

type serverManager struct {

}

type dbConnector interface {

}

func NewServerManager(db dbConnector) *serverManager {
	return &serverManager{}
}

func (s *serverManager) Register(ctx context.Context, login, password string) (id string, err error) {
	//TODO
	return "", nil
}
func (s *serverManager) Login(ctx context.Context, login, password string) (id, token string, err error) {
	//TODO
	return "", "", nil
}
func (s *serverManager) Auth(ctx context.Context, token string) (userID string, err error) {
	//TODO
	return "", nil
}
func (s *serverManager) CheckAndLockUser(ctx context.Context, userID, password string) error {
	//TODO
	return nil
}
func (s *serverManager) UnlockUser(ctx context.Context, userID string) error {
	//TODO
	return nil
}
func (s *serverManager) UpdatePass(ctx context.Context, userID, password string) error {
	//TODO
	return nil
}