package db

type connector struct {

}

func NewConnector(dsn string) (*connector, error) {
	return &connector{}, nil
}

func (c *connector) Close() {

}