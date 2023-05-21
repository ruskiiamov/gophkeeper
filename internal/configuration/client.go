// Package configuration is the tool for all apps configurations.
package configuration

type clientConfig struct {
}

// ReadClientConfig reads all client configuration from the set sources
// and returns the object for receiving all necessary values.
func ReadClientConfig() *clientConfig {
	return &clientConfig{}
}

// GetLocalDSN returns DSN for the local DB.
func (c *clientConfig) GetLocalDSN() string {
	return "./test.db" //TODO
}

// GetServerAddr returns gRPC server address.
func (c *clientConfig) GetServerAddr() string {
	return ":3200" //TODO
}

// GetFilesPath returns path for the local encrypted files storage.
func (c *clientConfig) GetFilesPath() string {
	return "./client_data" //TODO
}
