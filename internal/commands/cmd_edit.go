package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var editMultiline bool

var editCmd = &cobra.Command{
	Use:     "edit <key name>",
	Short:   "Edit an existing password",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		keyID := encrypt.KeyID(keyName)

		if _, _, err := store.GetKey(keyID); err != nil {
			return fmt.Errorf("key does not exist: %s", keyName)
		}

		var password string

		if editMultiline {
			fmt.Printf("Enter new contents for %s (Ctrl+D to finish):\n", keyName)

			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			password = strings.TrimSuffix(string(data), "\n")
		} else {
			fmt.Printf("Enter new password for %s: ", keyName)

			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read password: %w", err)
			}

			password = strings.TrimSuffix(line, "\n")
			password = strings.TrimSuffix(password, "\r")
		}

		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		payload := vault.Payload{
			Data: password,
		}

		payloadEncoded, err := payload.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encValue, err := encrypt.EncryptValue(keyName, payloadEncoded)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(keyID, encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Println("Password updated successfully:", keyName)

		return nil
	},
}

func init() {
	editCmd.Flags().BoolVarP(&editMultiline, "multiline", "m", false, "Read multi-line input until Ctrl+D")
}
