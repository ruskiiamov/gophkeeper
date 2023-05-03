package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	addCmd.PersistentFlags().StringVarP(&description, "description", "d", "", "Custom data description")

	cardCmd.Flags().StringVarP(&number, "number", "n", "", "Bank card number (required)")
	cardCmd.Flags().StringVarP(&owner, "owner", "o", "", "Bank card owner (required)")
	cardCmd.Flags().StringVarP(&date, "expire", "e", "", "Bank card expire date (required)")
	cardCmd.Flags().StringVarP(&code, "code", "c", "", "Bank card CVV/CVC (required)")
	cardCmd.Flags().StringVarP(&pin, "pin", "p", "", "Bank card pin-code (required)")

	cardCmd.MarkFlagRequired("number")
	cardCmd.MarkFlagRequired("owner")
	cardCmd.MarkFlagRequired("expire")
	cardCmd.MarkFlagRequired("code")
	cardCmd.MarkFlagRequired("pin")

	addCmd.AddCommand(credCmd)
	addCmd.AddCommand(textCmd)
	addCmd.AddCommand(fileCmd)
	addCmd.AddCommand(cardCmd)
}

var (
	description string
	number      string
	owner       string
	date        string
	code        string
	pin         string
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add data to the system",
}

var credCmd = &cobra.Command{
	Use:   "creds <login> <password>",
	Short: "Add login-password pair to the system",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("adding creds %s / %s ...\n", args[0], args[1])
	},
}

var textCmd = &cobra.Command{
	Use:   "text '<any text>'",
	Short: "Add any text to the system",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("adding text %s ...\n", args[0])
	},
}

var fileCmd = &cobra.Command{
	Use:   "file <path/to/your/file>",
	Short: "Add file to the system",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("adding file %s ...\n", args[0])
		fmt.Printf("description: '%s'\n", description)
	},
}

var cardCmd = &cobra.Command{
	Use:   "card ",
	Short: "Add bank card data to the system",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("adding bank card %s ...\n", number)
	},
}
