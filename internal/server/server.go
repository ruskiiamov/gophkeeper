// Package server is the gRPC server implementation for Gophkeeper.
package server

import (
	"context"
	"fmt"
	"net"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	pb "github.com/ruskiiamov/gophkeeper/internal/proto"
	"google.golang.org/grpc"
)

type accessManager interface {
	Register(ctx context.Context, login, password string) (id string, err error)
	Login(ctx context.Context, login, password string) (id, token string, err error)
	Auth(ctx context.Context, token string) (userID string, err error)
	CheckAndLockUser(ctx context.Context, userID, password string) error
	UnlockUser(ctx context.Context, userID string) error
	UpdatePass(ctx context.Context, userID, password string) error
}

type dataKeeper interface {
	CheckAndLockEntry(ctx context.Context, id, userID string) error
	CheckAndLockEntries(ctx context.Context, userID string) error
	UnlockEntries(ctx context.Context, userID string) error
	UnlockEntry(ctx context.Context, id, userID string) error
	ForceDeleteEntries(ctx context.Context, userID string) error
	GetEntries(ctx context.Context, userID string) ([]*dto.ServerEntry, error)
	AddEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error)
	GetEntry(ctx context.Context, id, userID string, metadataCh chan<- *dto.ServerEntry, chunkCh chan<- []byte, errCh chan<- error)
	UpdateEntry(ctx context.Context, entry *dto.ServerEntry, chunkCh <-chan []byte, errCh chan<- error)
}

type server struct {
	grpc     *grpc.Server
	listener net.Listener
}

// New returns the object that handle all gRPCs.
func New(addr string, am accessManager, dk dataKeeper) (*server, error) {
	s := grpc.NewServer()

	listen, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("net listen error: %w", err)
	}

	pb.RegisterGophKeeperServer(s, &gkServer{
		am: am,
		dk: dk,
	})

	return &server{
		grpc:     s,
		listener: listen,
	}, nil
}

// Serve starts the gRPC server.
func (s *server) Serve() error {
	return s.grpc.Serve(s.listener)
}

// Stop stops the gRPC server.
func (s *server) Stop() {
	s.grpc.Stop()
}
