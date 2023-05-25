// Gophkeeper client.
package main

import (
	"github.com/ruskiiamov/gophkeeper/internal/access"
	"github.com/ruskiiamov/gophkeeper/internal/client"
	"github.com/ruskiiamov/gophkeeper/internal/commands"
	"github.com/ruskiiamov/gophkeeper/internal/configuration"
	"github.com/ruskiiamov/gophkeeper/internal/cryptor"
	"github.com/ruskiiamov/gophkeeper/internal/data"
	"github.com/ruskiiamov/gophkeeper/internal/localstorage"
)

var (
	buildVersion string = `"N/A"`
	buildDate    string = `"N/A"`
)

func main() {
	config := configuration.ReadClientConfig()

	storage, err := localstorage.New(config.GetLocalDSN())
	if err != nil {
		panic(err)
	}
	defer storage.Close()

	grpcClient, err := client.New(config.GetServerAddr())
	if err != nil {
		panic(err)
	}
	defer grpcClient.Close()

	accessManager := access.NewClientManager(storage, grpcClient)

	dataCryptor := cryptor.New()
	dataKeeper := data.NewClientKeeper(config.GetFilesPath(), dataCryptor, storage, grpcClient)

	cmd := commands.New(buildVersion, buildDate, accessManager, dataKeeper)
	cmd.Execute()
}
