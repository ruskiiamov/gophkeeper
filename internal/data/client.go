package data

type clientKeeper struct {

}

func NewClientKeeper(cipher, storage, client interface{}) *clientKeeper {
	//TODO
	return &clientKeeper{}
}

func (c *clientKeeper) CheckSync(token string) (bool, error) {
	//TODO
	return false, nil
}

func (c *clientKeeper) UpdateEncryption(userID, oldKey, newKey string) error {
	//TODO
	return nil
}
