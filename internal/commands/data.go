package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Data synchronization",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("synchronization ...\n")
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Show stored data list",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("list: ...\n")
	},
}

var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get data entry",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("data %s: ...\n", args[0])
	},
}
