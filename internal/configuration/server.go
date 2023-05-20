package configuration

type serverConfig struct {
}

func ReadServerConfig() *serverConfig {
	return &serverConfig{}
}

func (s *serverConfig) GetDSN() string {
	return "postgres://root:root@localhost:54320/gophkeeper?sslmode=disable" //TODO
}

func (s *serverConfig) GetAddr() string {
	return ":3200" //TODO
}

func (s *serverConfig) GetFilesPath() string {
	return "./server_data" //TODO
}

func (s *serverConfig) GetAuthSecret() string {
	return "secret" //TODO
}
