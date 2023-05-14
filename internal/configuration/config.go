package configuration

type config struct {
}

func ReadConfig() *config {
	return &config{}
}

func (c *config) GetLocalDSN() string {
	return "test.db" //TODO
}

func (c *config) GetServerAddr() string {
	return ":3200" //TODO
}

func (c *config) GetFilesPath() string {
	return "" //TODO
}
