package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var copyForce bool

var copyCmd = &cobra.Command{
	Use:     "copy <key name> <new key name>",
	Aliases: []string{"cp"},
	Short:   "Copy a stored key to a new location",
	Args:    cobra.ExactArgs(2),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		newKeyName := args[1]
		if err := vault.ValidateKeyName(newKeyName); err != nil {
			return err
		}

		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encNewKeyName, err := encrypt.EncryptKey(newKeyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt new key name: %w", err)
		}

		oldKeyPayload, err := store.GetKey(encKeyName)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		oldKeyPayloadDecrypted, err := encrypt.DecryptValue(keyName, oldKeyPayload)
		if err != nil {
			return fmt.Errorf("failed to decrypt key: %w", err)
		}

		if _, err = store.GetKey(encNewKeyName); err == nil {
			if !copyForce {
				return fmt.Errorf("destination key already exists, use --force to overwrite")
			}
		}

		newKeyPayload, err := encrypt.EncryptValue(newKeyName, oldKeyPayloadDecrypted)
		if err != nil {
			return fmt.Errorf("failed to encrypt new key: %w", err)
		}

		if err := store.SetKey(encNewKeyName, newKeyPayload); err != nil {
			return fmt.Errorf("failed to set key: %w", err)
		}

		fmt.Printf("Key successfully copied from %s to %s\n", keyName, newKeyName)

		return nil
	},
}

func init() {
	copyCmd.Flags().BoolVarP(&copyForce, "force", "f", false, "Force overwrite existing key")
}
