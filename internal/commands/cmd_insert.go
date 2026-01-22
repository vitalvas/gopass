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

var (
	insertForce     bool
	insertMultiline bool
)

var insertCmd = &cobra.Command{
	Use:     "insert <key name>",
	Aliases: []string{"set", "add"},
	Short:   "Insert a new password",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		keyID := encrypt.KeyID(keyName)

		if _, _, err := store.GetKey(keyID); err == nil {
			if !insertForce {
				return fmt.Errorf("key already exists, use --force to overwrite")
			}
		}

		var password string

		if insertMultiline {
			fmt.Printf("Enter contents for %s (Ctrl+D to finish):\n", keyName)

			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			password = strings.TrimSuffix(string(data), "\n")
		} else {
			fmt.Printf("Enter password for %s: ", keyName)

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

		fmt.Println("Password stored successfully:", keyName)

		return nil
	},
}

func init() {
	insertCmd.Flags().BoolVarP(&insertForce, "force", "f", false, "Force overwrite existing key")
	insertCmd.Flags().BoolVarP(&insertMultiline, "multiline", "m", false, "Read multi-line input until Ctrl+D")
}
