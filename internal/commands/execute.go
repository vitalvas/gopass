package commands

import (
	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
	"github.com/vitalvas/gopass/internal/version"
)

var vaultName string

var rootCmd = &cobra.Command{
	Use:     "gopass",
	Short:   "Simple password manager",
	Version: version.Version(),
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return vault.ValidateName(vaultName)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultName, "vault", "default", "Vault name")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(pwgenCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(insertCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(moveCmd)
	rootCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(grepCmd)
}
