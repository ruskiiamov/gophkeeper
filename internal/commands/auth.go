package commands

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	minPasswordLen = 8
	minLoginLen = 6
)

func registerCmd(am accessManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		login := args[0]
		if len(login) < minLoginLen {
			return errors.New("login too short")
		}

		password := args[1]
		if len(password) < minPasswordLen {
			return errors.New("password too short")
		}

		err := am.Register(login, password)
		if err != nil {
			return err
		}

		err = am.Login(login, password)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "reg <login> <password>",
		Short: "Register new user",
		Args:  cobra.ExactArgs(2),
		RunE:  run,
	}
}

func loginCmd(am accessManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		login := args[0]
		password := args[1]

		err := am.Login(login, password)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "auth <login> <password>",
		Short: "User authentication",
		Args:  cobra.ExactArgs(2),
		RunE:  run,
	}
}

func updatePassCmd(am accessManager, dm dataManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		newPassword := args[0]
		if len(newPassword) < minPasswordLen {
			return errors.New("password too short")
		}

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		ok, err := dm.CheckSync(creds.Token)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("synchronization required")
		}

		newKey, err := am.UpdatePass(creds.Token, newPassword)
		if err != nil {
			return err
		}

		err = dm.UpdateEncryption(creds.UserID, creds.Key, newKey)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "updpass <new_password>",
		Short: "Update user password",
		Args:  cobra.ExactArgs(1),
		RunE:  run,
	}
}
