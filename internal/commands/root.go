package commands

import (
	"context"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/spf13/cobra"
)

type accessManager interface {
	Register(ctx context.Context, login, password string) error
	Login(ctx context.Context, login, password string) (creds *dto.Creds, credsNotChanged bool, err error)
	GetCreds(ctx context.Context) (*dto.Creds, error)
	GetCredsByLogin(ctx context.Context, login string) (*dto.Creds, error)
	GetKey(ctx context.Context, login, password string) []byte
	UpdateCredsAndAuthenticate(ctx context.Context, login, password, token string) error
	UpdatePass(ctx context.Context, creds *dto.Creds, oldPassword, newPassword string) error
	Logout(ctx context.Context) error
}

type dataManager interface {
	CheckSync(ctx context.Context, creds *dto.Creds) (bool, error)
	UpdateEncryption(ctx context.Context, creds *dto.Creds, newKey []byte) error
	AddLogPass(ctx context.Context, creds *dto.Creds, lp *dto.LogPass, description string) error
	AddText(ctx context.Context, creds *dto.Creds, text, description string) error
	AddFile(ctx context.Context, creds *dto.Creds, path, description string) error
	AddCard(ctx context.Context, creds *dto.Creds, card *dto.Card, description string) error
	Sync(ctx context.Context, creds *dto.Creds) error
	GetList(ctx context.Context, creds *dto.Creds) ([]*dto.ClientEntry, error)
	GetEntry(ctx context.Context, creds *dto.Creds, id string) (*dto.ClientEntry, error)
	GetLogPass(ctx context.Context, creds *dto.Creds, id string) (*dto.LogPass, error)
	GetText(ctx context.Context, creds *dto.Creds, id string) (string, error)
	GetFile(ctx context.Context, creds *dto.Creds, id string) (string, error)
	GetCard(ctx context.Context, creds *dto.Creds, id string) (*dto.Card, error)
}

func New(am accessManager, dm dataManager) *cobra.Command {
	cmd := &cobra.Command{Use: "gophkeeper"}

	cmd.AddCommand(
		registerCmd(am),
		loginCmd(am, dm),
		updatePassCmd(am, dm),
		addCmd(am, dm),
		syncCmd(am, dm),
		listCmd(am, dm),
		getCmd(am, dm),
		//TODO update,
		//TODO delete,
	)

	return cmd
}
