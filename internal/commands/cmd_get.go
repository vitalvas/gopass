package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/pkg/vault"
)

var getCmd = &cobra.Command{
	Use:     "get <key name>",
	Short:   "Get a stored key",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encValue, err := store.GetKey(encKeyName)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(keyName, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		fmt.Println(payload.Data)

		return nil
	},
}
