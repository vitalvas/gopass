package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/vault"
)

func init() {
	commands = append(commands, delCmd)
}

var delCmd = &cli.Command{
	Name:      "del",
	Usage:     "Delete a key",
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

		return store.DeleteKey(encKeyName)
	},
}
