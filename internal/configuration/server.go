package configuration

type serverConfig struct {
}

func ReadServerConfig() *serverConfig {
	return &serverConfig{}
}

func (s *serverConfig) GetDSN() string {
	return "test.db" //TODO
}

func (s *serverConfig) GetAddr() string {
	return ":3200" //TODO
}

func (s *serverConfig) GetFilesPath() string {
	return "" //TODO
}

func (s *serverConfig) GetAuthSecret() string {
	return ""//TODO
}