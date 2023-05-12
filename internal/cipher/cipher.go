package cipher

type cipher struct {

}

func New() *cipher {
	return &cipher{}
}

func (c *cipher) Init(key string) error {
	//TODO
	return nil
}

func (c *cipher) Encrypt(chunk []byte) ([]byte, error) {
	//TODO
	return []byte{}, nil
}

func (c *cipher) Decrypt(chunk []byte) ([]byte, error) {
	//TODO
	return []byte{}, nil
}
