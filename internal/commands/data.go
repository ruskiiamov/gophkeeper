package commands

import (
	"fmt"

	"github.com/ruskiiamov/gophkeeper/internal/enum"
	"github.com/spf13/cobra"
)

func syncCmd(am accessManager, dm dataManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		err = dm.Sync(creds)
		if err != nil {
			return err
		}

		return nil
	}
	
	return &cobra.Command{
		Use:   "sync",
		Short: "Data synchronization",
		RunE: run,
	}
}

func listCmd(am accessManager, dm dataManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		list, err := dm.GetList(creds)
		if err != nil {
			return err
		}

		fmt.Println(list)//TODO show results in table

		return nil
	}
	
	return &cobra.Command{
		Use:   "list",
		Short: "Show stored data list",
		RunE: run,
	}
}

func getCmd(am accessManager, dm dataManager) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		id := args[0]

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		entry, err := dm.GetEntry(creds, id)
		if err != nil {
			return err
		}

		switch entry.Type {
		case enum.LogPass:
			logPass, err := dm.GetLogPass(creds, id)
			if err != nil {
				return err
			}
			fmt.Printf("Login: %s\n", logPass.Login)
			fmt.Printf("Password: %s\n", logPass.Password)
		case enum.Text:
			text, err := dm.GetText(creds, id)
			if err != nil {
				return err
			}
			fmt.Println(text)
		case enum.File:
			path, err := dm.GetFile(creds, id)
			if err != nil {
				return err
			}
			fmt.Printf("File path: %s\n", path)
		case enum.Card:
			card, err := dm.GetCard(creds, id)
			if err != nil {
				return err
			}
			fmt.Printf("Number: %s\n", card.Number)
			fmt.Printf("Owner: %s\n", card.Owner)
			fmt.Printf("Expire: %s\n", card.Expire)
			fmt.Printf("Code: %s\n", card.Code)
			fmt.Printf("Pin: %s\n", card.Pin)
		default:
			return fmt.Errorf("wrong data type %s", entry.Type)
		}

		return nil
	}
	
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get data entry",
		Args: cobra.ExactArgs(1),
		RunE: run,
	}
}
