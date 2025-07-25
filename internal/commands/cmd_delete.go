package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var deleteForce bool

var deleteCmd = &cobra.Command{
	Use:     "delete <key name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a stored key",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		var confirm string

		if !deleteForce {
			fmt.Printf("Are you sure you would like to delete %s? [y/N] ", keyName)

			if _, err := fmt.Scanln(&confirm); err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
		}

		if confirm == "y" || deleteForce {
			encKeyName, err := encrypt.EncryptKey(keyName)
			if err != nil {
				return fmt.Errorf("failed to encrypt key name: %w", err)
			}

			if err := store.DeleteKey(encKeyName); err != nil {
				return fmt.Errorf("failed to delete key: %w", err)
			}

			fmt.Println("Key deleted:", keyName)
		} else {
			fmt.Println("Deletion aborted")
		}

		return nil
	},
}

func init() {
	deleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Force delete key")
}
