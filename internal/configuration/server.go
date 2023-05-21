package configuration

type serverConfig struct {
}

// ReadServerConfig reads all server configuration from the set sources
// and returns the object for receiving all necessary values.
func ReadServerConfig() *serverConfig {
	return &serverConfig{}
}

// GetDSN returns DSN for the server DB. 
func (s *serverConfig) GetDSN() string {
	return "postgres://root:root@localhost:54320/gophkeeper?sslmode=disable" //TODO
}

// GetAddr returns address for the gRPC server.
func (s *serverConfig) GetAddr() string {
	return ":3200" //TODO
}

// GetFilesPath returns path for the encrypted files storage.
func (s *serverConfig) GetFilesPath() string {
	return "./server_data" //TODO
}

// GetAuthSecret returns the secret for the JWT signing.
func (s *serverConfig) GetAuthSecret() string {
	return "secret" //TODO
}
