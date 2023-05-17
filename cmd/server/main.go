package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/ruskiiamov/gophkeeper/internal/access"
	"github.com/ruskiiamov/gophkeeper/internal/configuration"
	"github.com/ruskiiamov/gophkeeper/internal/data"
	"github.com/ruskiiamov/gophkeeper/internal/db"
	"github.com/ruskiiamov/gophkeeper/internal/file"
	"github.com/ruskiiamov/gophkeeper/internal/server"
	"golang.org/x/sync/errgroup"
)

func main() {
	config := configuration.ReadServerConfig()

	dbConnector, err := db.NewConnector(config.GetDSN())
	if err != nil {
		panic(err)
	}

	fileStorage := file.NewStorage(config.GetFilesPath())

	accessManager := access.NewServerManager(dbConnector)
	dataKeeper := data.NewServerKeeper(dbConnector, fileStorage)

	server, err := server.New(config.GetAddr(), accessManager, dataKeeper)
	if err != nil {
		panic(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return server.Serve()
	})

	g.Go(func() error {
		<-ctx.Done()

		server.Stop()
		dbConnector.Close()

		return nil
	})
}
