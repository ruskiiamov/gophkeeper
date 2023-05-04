package commands

import (
	"os"

	"github.com/ruskiiamov/gophkeeper/internal/dto"
	"github.com/spf13/cobra"
)

func addCmd(am accessManager, dm dataManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add data to the system",
	}

	var description string
	cmd.PersistentFlags().StringVarP(&description, "description", "d", "", "Custom data description")

	cmd.AddCommand(
		logPassCmd(am, dm, description), 
		textCmd(am, dm, description),
		fileCmd(am, dm, description),
		cardCmd(am, dm, description),
	)

	return cmd
}

func logPassCmd(am accessManager, dm dataManager, d string) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		lp := &dto.LogPass{
			Login: args[0],
			Password: args[1],
		}

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		err = dm.AddLogPass(creds, lp, d)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "logpass <login> <password>",
		Short: "Add login-password pair to the system",
		Args:  cobra.ExactArgs(2),
		RunE: run,
	}
}

func textCmd(am accessManager, dm dataManager, d string) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		text := args[0]

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		err = dm.AddText(creds, text, d)
		if err != nil {
			return err
		}

		return nil
	}
	
	return  &cobra.Command{
		Use:   "text '<any text>'",
		Short: "Add any text to the system",
		Args:  cobra.ExactArgs(1),
		RunE: run,
	}
}

func fileCmd(am accessManager, dm dataManager, d string) *cobra.Command {
	run := func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return err
		}

		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		err = dm.AddFile(creds, path, d)
		if err != nil {
			return err
		}

		return nil
	}

	return &cobra.Command{
		Use:   "file <path/to/your/file>",
		Short: "Add file to the system",
		Args:  cobra.ExactArgs(1),
		RunE: run,
	}
}

func cardCmd(am accessManager, dm dataManager, d string) *cobra.Command {
	card := new(dto.Card)
	
	run := func(cmd *cobra.Command, args []string) error {
		creds, err := am.GetCreds()
		if err != nil {
			return err
		}

		err = dm.AddCard(creds, card, d)
		if err != nil {
			return err
		}

		return nil
	}
	
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Add bank card data to the system",
		RunE: run,
	}

	cmd.Flags().StringVarP(&(card.Number), "number", "n", "", "Bank card number (required)")
	cmd.Flags().StringVarP(&(card.Owner), "owner", "o", "", "Bank card owner (required)")
	cmd.Flags().StringVarP(&(card.Expire), "expire", "e", "", "Bank card expire date (required)")
	cmd.Flags().StringVarP(&(card.Code), "code", "c", "", "Bank card CVV/CVC (required)")
	cmd.Flags().StringVarP(&(card.Pin), "pin", "p", "", "Bank card pin-code (required)")
	cmd.MarkFlagRequired("number")
	cmd.MarkFlagRequired("owner")
	cmd.MarkFlagRequired("expire")
	cmd.MarkFlagRequired("code")
	cmd.MarkFlagRequired("pin")
	
	return cmd
}
