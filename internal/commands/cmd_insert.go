package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var insertForce bool

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

		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		if _, err := store.GetKey(encKeyName); err == nil {
			if !insertForce {
				return fmt.Errorf("key already exists, use --force to overwrite")
			}
		}

		fmt.Printf("Enter password for %s: ", keyName)

		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		password = strings.TrimSuffix(password, "\n")
		password = strings.TrimSuffix(password, "\r")

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

		encValue, err := encrypt.EncryptValue(keyName, payloadEncoded)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Println("Password stored successfully:", keyName)

		return nil
	},
}

func init() {
	insertCmd.Flags().BoolVarP(&insertForce, "force", "f", false, "Force overwrite existing key")
}
