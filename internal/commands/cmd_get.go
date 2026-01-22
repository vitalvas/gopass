package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/qrcode"
	"github.com/vitalvas/gopass/internal/vault"
)

var getQRCode bool

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

		keyID := encrypt.KeyID(keyName)

		_, encValue, err := store.GetKey(keyID)
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

		if getQRCode {
			return qrcode.Print(os.Stdout, payload.Data)
		}

		fmt.Println(payload.Data)

		return nil
	},
}

func init() {
	getCmd.Flags().BoolVarP(&getQRCode, "qrcode", "q", false, "Display as QR code")
}
