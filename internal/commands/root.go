package commands

import (
	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/spf13/cobra"
)

type accessManager interface {
	Register(login, password string) error
	Login(login, password string) error
	GetCreds() (*dto.Creds, error)
	UpdatePass(token, newPassword string) (newKey string, err error)
}

type dataManager interface {
	CheckSync(token string) (bool, error)
	UpdateEncryption(userID, oldKey, newKey string) error
}

func New(am accessManager, dm dataManager) *cobra.Command {
	rootCmd := &cobra.Command{Use: "gophkeeper"}

	rootCmd.AddCommand(
		registerCmd(am), 
		loginCmd(am),
		updatePassCmd(am, dm),
		addCmd,
		syncCmd,
		listCmd,
		getCmd,
		//TODO update,
		//TODO delete,
	)

	return rootCmd
}
