package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var moveForce bool

var moveCmd = &cobra.Command{
	Use:     "move <key name> <new key name>",
	Aliases: []string{"mv"},
	Short:   "Move a stored key",
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

		keyID := encrypt.KeyID(keyName)
		newKeyID := encrypt.KeyID(newKeyName)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		decryptedValue, err := encrypt.DecryptValue(keyName, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt key: %w", err)
		}

		newEncKeyName, err := encrypt.EncryptKey(newKeyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt new key name: %w", err)
		}

		newEncValue, err := encrypt.EncryptValue(newKeyName, decryptedValue)
		if err != nil {
			return fmt.Errorf("failed to encrypt new key: %w", err)
		}

		if _, _, err = store.GetKey(newKeyID); err == nil {
			if !moveForce {
				return fmt.Errorf("new key already exists")
			}

			if err := store.DeleteKey(newKeyID); err != nil {
				return fmt.Errorf("failed to delete key from new key path: %w", err)
			}
		}

		if err := store.SetKey(newKeyID, newEncKeyName, newEncValue); err != nil {
			return fmt.Errorf("failed to set key: %w", err)
		}

		if err := store.DeleteKey(keyID); err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}

		fmt.Printf("Key successful moved from %s to %s\n", keyName, newKeyName)

		return nil
	},
}

func init() {
	moveCmd.Flags().BoolVarP(&moveForce, "force", "f", false, "Force overwrite existing key")
}
