package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
	pb "github.com/ruskiiamov/gophkeeper/internal/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	mdAuthorization = "authorization"
	mdID            = "id"
	mdUserID        = "user_id"
	mdMetadata      = "metadata"
)

type gkServer struct {
	pb.UnimplementedGophKeeperServer
	am accessManager
	dk dataKeeper
}

// Register handles simple RPC for register new user.
func (g *gkServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	id, err := g.am.Register(ctx, in.Login, in.Password)
	if errors.Is(err, errs.ErrUserExists) {
		return nil, status.Error(codes.AlreadyExists, err.Error())
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RegisterResponse{Id: id}, nil
}

// Login handles simple RPC for user authentication.
func (g *gkServer) Login(ctx context.Context, in *pb.LoginRequest) (*pb.LoginResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	id, token, err := g.am.Login(ctx, in.Login, in.Password)
	if errors.Is(err, errs.ErrUnauthenticated) {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.LoginResponse{Id: id, Token: token}, nil
}

// UpdatePass handles simple RPC for user password update.
func (g *gkServer) UpdatePass(ctx context.Context, in *pb.UpdatePassRequest) (*pb.UpdatePassResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	userID, err := g.auth(ctx)
	if err != nil {
		return nil, err
	}

	err = g.dk.CheckAndLockEntries(ctx, userID)
	if errors.Is(err, errs.ErrLocked) {
		return nil, status.Error(codes.Aborted, err.Error())
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer g.dk.UnlockEntries(ctx, userID)

	err = g.am.CheckAndLockUser(ctx, userID, in.OldPassword)
	if errors.Is(err, errs.ErrLocked) {
		return nil, status.Error(codes.Aborted, err.Error())
	}
	if errors.Is(err, errs.ErrWrongPassword) {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer g.am.UnlockUser(ctx, userID)

	err = g.dk.ForceDeleteEntries(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	err = g.am.UpdatePass(ctx, userID, in.NewPassword)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UpdatePassResponse{}, nil
}

// GetEntries handles simple RPC for getting user server side entries.
func (g *gkServer) GetEntries(ctx context.Context, in *pb.GetEntriesRequest) (*pb.GetEntriesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	userID, err := g.auth(ctx)
	if err != nil {
		return nil, err
	}

	entries, err := g.dk.GetEntries(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	grpcEntries := make([]*pb.Entry, len(entries))
	for i, entry := range entries {
		grpcEntry := &pb.Entry{
			Id:       entry.ID,
			UserId:   entry.UserID,
			Metadata: entry.Metadata,
		}
		grpcEntries[i] = grpcEntry
	}

	return &pb.GetEntriesResponse{Entry: grpcEntries}, nil
}

// AddEntry handle client-side streaming RPC for adding data to the server.
func (g *gkServer) AddEntry(stream pb.GophKeeper_AddEntryServer) error {
	ctx, cancel := context.WithTimeout(stream.Context(), 90*time.Second)
	defer cancel()

	userID, err := g.auth(ctx)
	if err != nil {
		return err
	}

	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get(mdID)) < 1 || len(md.Get(mdUserID)) < 1 || len(md.Get(mdMetadata)) < 1 {
		return status.Error(codes.InvalidArgument, "lack of entry metadata")
	}

	metadata, err := base64.StdEncoding.DecodeString(md.Get(mdMetadata)[0])
	if err != nil {
		return fmt.Errorf("base64 decoding error: %w", err)
	}

	entry := &dto.ServerEntry{
		ID:       md.Get(mdID)[0],
		UserID:   md.Get(mdUserID)[0],
		Metadata: metadata,
	}
	if userID != entry.UserID {
		return status.Error(codes.InvalidArgument, "wrong user id")
	}

	//TODO check entry exists

	chunkCh := make(chan []byte)
	errCh := make(chan error)
	go g.dk.AddEntry(ctx, entry, chunkCh, errCh)

	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "context done")
		case err := <-errCh:
			if err != nil {
				return status.Error(codes.Internal, err.Error())
			}
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		chunkCh <- req.Chunk
	}

	close(chunkCh)

	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, "context done")
	case err = <-errCh:
	}
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return stream.SendAndClose(&pb.AddEntryResponse{})
}

// GetEntry handles server-side streaming RPC for getting data from the server.
func (g *gkServer) GetEntry(in *pb.GetEntryRequest, stream pb.GophKeeper_GetEntryServer) error {
	ctx, cancel := context.WithTimeout(stream.Context(), 90*time.Second)
	defer cancel()

	userID, err := g.auth(ctx)
	if err != nil {
		return err
	}

	//TODO check entry exists

	metadataCh := make(chan *dto.ServerEntry)
	chunkCh := make(chan []byte)
	errCh := make(chan error)
	go g.dk.GetEntry(ctx, in.Id, userID, metadataCh, chunkCh, errCh)

	entry := new(dto.ServerEntry)
	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, "context done")
	case err := <-errCh:
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	case entry = <-metadataCh:
	}

	err = stream.SendHeader(metadata.Pairs(
		mdID, entry.ID,
		mdUserID, entry.UserID,
		mdMetadata, base64.StdEncoding.EncodeToString(entry.Metadata),
	))
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "context done")
		case err := <-errCh:
			if err != nil {
				return status.Error(codes.Internal, err.Error())
			}
		default:
		}

		chunk, ok := <-chunkCh
		if !ok {
			break
		}

		err = stream.Send(&pb.GetEntryResponse{Chunk: chunk})
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, "context done")
	case err = <-errCh:
	}
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return nil
}

// UpdateEntry handles bidirectional streaming RPC for updating data on the
// server side after confirmation.
func (g *gkServer) UpdateEntry(stream pb.GophKeeper_UpdateEntryServer) error {
	ctx, cancel := context.WithTimeout(stream.Context(), 90*time.Second)
	defer cancel()

	userID, err := g.auth(ctx)
	if err != nil {
		return err
	}

	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get(mdID)) < 1 || len(md.Get(mdUserID)) < 1 || len(md.Get(mdMetadata)) < 1 {
		return status.Error(codes.InvalidArgument, "lack of entry metadata")
	}

	metadata, err := base64.StdEncoding.DecodeString(md.Get(mdMetadata)[0])
	if err != nil {
		return fmt.Errorf("base64 decoding error: %w", err)
	}

	entry := &dto.ServerEntry{
		ID:       md.Get(mdID)[0],
		UserID:   md.Get(mdUserID)[0],
		Metadata: metadata,
	}
	if userID != entry.UserID {
		return status.Error(codes.InvalidArgument, "wrong user id")
	}

	err = g.dk.CheckAndLockEntry(ctx, entry.ID, userID)
	if errors.Is(err, errs.ErrLocked) {
		return status.Error(codes.Aborted, err.Error())
	}
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer g.dk.UnlockEntry(ctx, entry.ID, userID)

	if err = stream.Send(&pb.UpdateEntryResponse{Confirmation: true}); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	chunkCh := make(chan []byte)
	errCh := make(chan error)
	go g.dk.UpdateEntry(ctx, entry, chunkCh, errCh)

	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "context done")
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		chunkCh <- req.Chunk
	}

	close(chunkCh)

	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, "context done")
	case err = <-errCh:
	}
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return nil
}

// DeleteEntry handles simple RPC for deleting data on the server side.
func (g *gkServer) DeleteEntry(ctx context.Context, in *pb.DeleteEntryRequest) (*pb.DeleteEntryResponse, error) {
	//TODO
	return &pb.DeleteEntryResponse{}, nil
}

func (g *gkServer) auth(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get(mdAuthorization)) < 1 {
		return "", status.Error(codes.Unauthenticated, "auth token is needed")
	}
	token := md.Get(mdAuthorization)[0]

	userID, err := g.am.Auth(ctx, token)
	if errors.Is(err, errs.ErrUnauthenticated) {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}

	return userID, nil
}
