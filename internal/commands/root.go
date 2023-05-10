package commands

import (
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/spf13/cobra"
)

type accessManager interface {
	Register(login, password string) error
	Login(login, password string) (credsNotChanged bool, err error)
	GetCreds() (*dto.Creds, error)
	GetCredsByLogin(login string) (*dto.Creds, error)
	GetKey(password string) (string, error)
	UpdateCreds(login, password string) error
	UpdatePass(creds *dto.Creds, oldPassword, newPassword string) error
	Logout(creds *dto.Creds) error
}

type dataManager interface {
	CheckSync(*dto.Creds) (bool, error)
	UpdateEncryption(creds *dto.Creds, newKey string) error
	AddLogPass(creds *dto.Creds, lp *dto.LogPass, description string) error
	AddText(creds *dto.Creds, text, description string) error
	AddFile(creds *dto.Creds, path, description string) error
	AddCard(creds *dto.Creds, card *dto.Card, description string) error
	Sync(creds *dto.Creds) error
	GetList(creds *dto.Creds) ([]*dto.Entry, error)
	GetEntry(creds *dto.Creds, id string) (*dto.Entry, error)
	GetLogPass(creds *dto.Creds, id string) (*dto.LogPass, error)
	GetText(creds *dto.Creds, id string) (string, error)
	GetFile(creds *dto.Creds, id string) (string, error)
	GetCard(creds *dto.Creds, id string) (*dto.Card, error)
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
