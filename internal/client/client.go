package client

import (
	"context"
	"io"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	pb "github.com/ruskiiamov/gophkeeper/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	conn *grpc.ClientConn
	c    pb.GophKeeperClient
}

func New(serverAddr string) (*client, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials())) //TODO
	if err != nil {
		return nil, err
	}

	c := pb.NewGophKeeperClient(conn)

	return &client{
		conn: conn,
		c:    c,
	}, nil
}

func (c *client) Close() {
	c.conn.Close()
}

func (c *client) Register(ctx context.Context, login, password string) (id string, err error) {
	//TODO
	return "", nil
}

func (c *client) Login(ctx context.Context, login, password string) (id, token string, err error) {
	//TODO
	return "", "", nil
}

func (c *client) UpdatePass(ctx context.Context, token, oldPassword, newPassword string) error {
	//TODO
	return nil
}

func (c *client) GetEntries(ctx context.Context, token string) ([]*dto.ServerEntry, error) {
	//TODO
	return []*dto.ServerEntry{}, nil
}

func (c *client) AddEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error {
	//TODO
	return nil
}

func (c *client) GetEntry(ctx context.Context, token, id string, dst io.Writer) (*dto.ServerEntry, error) {
	//TODO
	return &dto.ServerEntry{}, nil
}

func (c *client) UpdateEntry(ctx context.Context, token string, entry *dto.ServerEntry, src io.Reader) error {
	//TODO
	return nil
}
