package client

import (
	pb "github.com/ruskiiamov/gophkeeper/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	conn *grpc.ClientConn
	c pb.GophKeeperClient
}

func New(serverAddr string) (*client, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials())) //TODO
	if err != nil {
		return nil, err
	}

	c := pb.NewGophKeeperClient(conn)
	
	return &client{
		conn: conn,
		c: c,
	}, nil
}

func (c *client) Close() {
	c.conn.Close()
}