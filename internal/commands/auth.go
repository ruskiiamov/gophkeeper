package commands

import (
	"context"
	"errors"
	"time"

	"github.com/ruskiiamov/gophkeeper/internal/errs"
	"github.com/spf13/cobra"
)

const (
	minPasswordLen = 8
	minLoginLen    = 6
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := am.Register(ctx, login, password)
		if errors.Is(err, errs.ErrUserExists) {
			return errors.New("user already exists")
		}
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

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		creds, credsNotChanged, err := am.Login(ctx, login, password)
		if errors.Is(err, errs.ErrUnauthenticated) {
			return errors.New("wrong login password pair")
		}
		if err != nil {
			return err
		}

		if credsNotChanged {
			return nil
		}

		oldCreds, err := am.GetCredsByLogin(ctx, login)
		if err != nil {
			return nil
		}

		newKey := am.GetKey(ctx, login, password)
		err = dm.UpdateEncryption(ctx, oldCreds, newKey)
		if err != nil {
			return err
		}

		err = am.UpdateCredsAndAuthenticate(ctx, login, password, creds.Token)
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

		if oldPassword == newPassword {
			return errors.New("passwords are equal")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		creds, err := am.GetCreds(ctx)
		if errors.Is(err, errs.ErrUnauthenticated) {
			return errors.New("auth is needed")
		}
		if err != nil {
			return err
		}

		ok, err := dm.CheckSync(ctx, creds)
		if errors.Is(err, errs.ErrUnauthenticated) {
			return errors.New("auth is needed")
		}
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("synchronization required")
		}

		err = am.UpdatePass(ctx, creds, oldPassword, newPassword)
		if errors.Is(err, errs.ErrUnauthenticated) {
			return errors.New("auth is needed")
		}
		if errors.Is(err, errs.ErrWrongPassword) {
			return errors.New("wrong old password")
		}
		if errors.Is(err, errs.ErrEntryLocked) {
			return errors.New("entry locked by other client")
		}
		if err != nil {
			return err
		}

		err = am.Logout(ctx)
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
