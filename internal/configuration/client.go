package configuration

type clientConfig struct {
}

func ReadClientConfig() *clientConfig {
	return &clientConfig{}
}

func (c *clientConfig) GetLocalDSN() string {
	return "./test.db" //TODO
}

func (c *clientConfig) GetServerAddr() string {
	return ":3200" //TODO
}

func (c *clientConfig) GetFilesPath() string {
	return "./client_data" //TODO
}
