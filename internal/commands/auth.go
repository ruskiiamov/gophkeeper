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

		_, err = am.Login(login, password)
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

func loginCmd(am accessManager, dm dataManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		login := args[0]
		password := args[1]

		credsNotChanged, err := am.Login(login, password)
		if err != nil {
			return err
		}

		if credsNotChanged {
			return nil
		}

		creds, err := am.GetCredsByLogin(login)
		if err != nil {
			return nil
		}

		key, err := am.GetKey(password)
		if err != nil {
			return err
		}

		err = dm.UpdateEncryption(creds, key)
		if err != nil {
			return err
		}

		err = am.UpdateCreds(login, password)
		if err != nil {
			return err
		}

		_, err = am.Login(login, password)
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
		oldPassword := args[0]
		newPassword := args[1]
		if len(newPassword) < minPasswordLen {
			return errors.New("password too short")
		}

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		ok, err := dm.CheckSync(creds)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("synchronization required")
		}

		err = am.UpdatePass(creds, oldPassword, newPassword)
		if err != nil {
			return err
		}

		err = am.Logout(creds)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "updpass <old_password> <new_password>",
		Short: "Update user password",
		Args:  cobra.ExactArgs(1),
		RunE:  run,
	}
}
