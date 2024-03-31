package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/vault"
)

var getCmd = &cli.Command{
	Name:      "get",
	Usage:     "Get a stored key",
	ArgsUsage: "<key name>",
	Before:    loader,
	Action: func(c *cli.Context) error {
		if c.Args().Len() != 1 {
			return fmt.Errorf("invalid number of arguments")
		}

		keyName := c.Args().First()
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

		fmt.Println(string(value))

		return nil
	},
}
