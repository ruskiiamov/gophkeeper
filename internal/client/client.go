package client

import (
	"io"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
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

func (c *client) GetEntries(token string) ([]*dto.Entry, error) {
	//TODO
	return []*dto.Entry{}, nil
}

func (c *client) AddEntry(token, id string, encryptedMetadata []byte, src io.Reader) error {
	//TODO
	return nil
}

func (c *client) GetEntry(token, id string, dst io.Writer) (encryptedMetadata []byte, err error) {
	//TODO
	return []byte{}, nil
}

func (c *client) UpdateEntry(token, id string, encryptedMetadata []byte, src io.Reader) error {
	//TODO
	return nil
}
