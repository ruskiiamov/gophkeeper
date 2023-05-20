package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/ruskiiamov/gophkeeper/internal/errs"
	pb "github.com/ruskiiamov/gophkeeper/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	mdAuthorization = "authorization"
	mdID            = "id"
	mdUserID        = "user_id"
	mdMetadata      = "metadata"
	chunkSize       = 64 * 1024
)

type client struct {
	conn *grpc.ClientConn
	grpc pb.GophKeeperClient
}

func New(serverAddr string) (*client, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials())) //TODO
	if err != nil {
		return nil, err
	}

	c := pb.NewGophKeeperClient(conn)

	return &client{
		conn: conn,
		grpc: c,
	}, nil
}

func (c *client) Close() {
	c.conn.Close()
}

func (c *client) Register(ctx context.Context, login, password string) (id string, err error) {
	resp, err := c.grpc.Register(ctx, &pb.RegisterRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			if e.Code() == codes.AlreadyExists {
				return "", errs.ErrUserExists
			}
			return "", fmt.Errorf("server error: %s", e.Message())
		}
		return "", fmt.Errorf("grpc register error: %w", err)
	}

	return resp.Id, nil
}

func (c *client) Login(ctx context.Context, login, password string) (id, token string, err error) {
	resp, err := c.grpc.Login(ctx, &pb.LoginRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			if e.Code() == codes.Unauthenticated {
				return "", "", errs.ErrUnauthenticated
			}
			return "", "", fmt.Errorf("server error: %s", e.Message())
		}
		return "", "", fmt.Errorf("grpc login error: %w", err)
	}

	return resp.Id, resp.Token, nil
}

func (c *client) UpdatePass(ctx context.Context, token, oldPassword, newPassword string) error {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(mdAuthorization, token))

	_, err := c.grpc.UpdatePass(ctx, &pb.UpdatePassRequest{
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Unauthenticated:
				return errs.ErrUnauthenticated
			case codes.InvalidArgument:
				return errs.ErrWrongPassword
			case codes.Aborted:
				return errs.ErrLocked
			}
			return fmt.Errorf("server error: %s", e.Message())
		}
		return fmt.Errorf("grpc update pass error: %w", err)
	}

	return nil
}

func (c *client) GetEntries(ctx context.Context, token string) ([]*dto.ServerEntry, error) {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(mdAuthorization, token))

	resp, err := c.grpc.GetEntries(ctx, &pb.GetEntriesRequest{})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			if e.Code() == codes.Unauthenticated {
				return nil, errs.ErrUnauthenticated
			}
			return nil, fmt.Errorf("server error: %s", e.Message())
		}
		return nil, fmt.Errorf("grpc get entries error: %w", err)
	}

	serverEntries := make([]*dto.ServerEntry, len(resp.Entry))
	for i, entry := range resp.Entry {
		serverEntry := &dto.ServerEntry{
			ID:       entry.Id,
			UserID:   entry.UserId,
			Metadata: entry.Metadata,
		}
		serverEntries[i] = serverEntry
	}

	return serverEntries, nil
}

func (c *client) AddEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		mdAuthorization, token,
		mdID, entry.ID,
		mdUserID, entry.UserID,
		mdMetadata, base64.StdEncoding.EncodeToString(entry.Metadata),
	))

	stream, err := c.grpc.AddEntry(ctx)
	if err != nil {
		return fmt.Errorf("grpc add entry error: %w", err)
	}

	chunk := make([]byte, chunkSize)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done")
		default:
		}

		n, err := src.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		err = stream.Send(&pb.AddEntryRequest{Chunk: chunk})
		if err != nil {
			return fmt.Errorf("stream send error: %w", err)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("stream close and recv error: %w", err)
	}

	return nil
}

func (c *client) GetEntry(ctx context.Context, token, id string, dst io.Writer) (*dto.ServerEntry, error) {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(mdAuthorization, token))

	stream, err := c.grpc.GetEntry(ctx, &pb.GetEntryRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("grpc get entry error: %w", err)
	}

	header, err := stream.Header()
	if err != nil {
		return nil, fmt.Errorf("stream header error: %w", err)
	}
	if len(header.Get(mdID)) < 1 || len(header.Get(mdUserID)) < 1 || len(header.Get(mdMetadata)) < 1 {
		return nil, errors.New("lack of entry metadata")
	}
	metadata, err := base64.StdEncoding.DecodeString(header.Get(mdMetadata)[0])
	if err != nil {
		return nil, fmt.Errorf("base64 decoding error: %w", err)
	}
	entry := &dto.ServerEntry{
		ID:       header.Get(mdID)[0],
		UserID:   header.Get(mdUserID)[0],
		Metadata: metadata,
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context done")
		default:
		}

		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("stream recv error: %w", err)
		}

		_, err = dst.Write(resp.Chunk)
		if err != nil {
			return nil, fmt.Errorf("dst write error: %w", err)
		}
	}

	return entry, nil
}

func (c *client) UpdateEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		mdAuthorization, token,
		mdID, entry.ID,
		mdUserID, entry.UserID,
		mdMetadata, base64.StdEncoding.EncodeToString(entry.Metadata),
	))

	stream, err := c.grpc.UpdateEntry(ctx)
	if err != nil {
		return fmt.Errorf("grpc update entry error: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("stream recv error: %w", err)
	}
	if !resp.Confirmation {
		stream.CloseSend()
		return errors.New("update entry not confirmed")
	}

	chunk := make([]byte, chunkSize)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context done")
		default:
		}

		n, err := src.Read(chunk)
		chunk = chunk[:n]
		if n == 0 && err == io.EOF {
			break
		}

		err = stream.Send(&pb.UpdateEntryRequest{Chunk: chunk})
		if err != nil {
			return fmt.Errorf("stream send error: %w", err)
		}
	}

	stream.CloseSend()

	return nil
}
