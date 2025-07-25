package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/pkg/password"
	"github.com/vitalvas/gopass/pkg/vault"
)

var generateForce bool

var generateCmd = &cobra.Command{
	Use:     "generate <key name>",
	Short:   "Generate and store a new password",
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

		if _, err := store.GetKey(encKeyName); err == nil {
			if !generateForce {
				return fmt.Errorf("key already exists, use --force to overwrite")
			}
		}
		pass := password.Generate(password.DefaultLength, password.DefaultLength, password.DefaultLength)

		payload := vault.Payload{
			Data: pass,
		}

		payloadEncoded, err := payload.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		encValue, err := encrypt.EncryptValue(keyName, payloadEncoded)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Println("Password generated and stored successfully:", keyName)

		return nil
	},
}

func init() {
	generateCmd.Flags().BoolVarP(&generateForce, "force", "f", false, "Force overwrite existing key")
}
