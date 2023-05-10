package main

import (
	"github.com/ruskiiamov/gophkeeper/internal/access"
	"github.com/ruskiiamov/gophkeeper/internal/cipher"
	"github.com/ruskiiamov/gophkeeper/internal/client"
	"github.com/ruskiiamov/gophkeeper/internal/commands"
	"github.com/ruskiiamov/gophkeeper/internal/configuration"
	"github.com/ruskiiamov/gophkeeper/internal/data"
	"github.com/ruskiiamov/gophkeeper/internal/localstorage"
)

func main() {
	config := configuration.ReadConfig()
	
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

	dataCipher := cipher.New()
	dataKeeper := data.NewClientKeeper(config.GetFilesPath(), dataCipher, storage, grpcClient)

	cmd := commands.New(accessManager, dataKeeper)
	cmd.Execute()
}
