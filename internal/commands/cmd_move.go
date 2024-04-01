package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/vault"
)

var moveCmd = &cli.Command{
	Name:      "move",
	Aliases:   []string{"mv"},
	Usage:     "Move a stored key",
	ArgsUsage: "<key name> <new key name>",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
			Usage:   "Force overwrite existing key",
		},
	},
	Before: loader,
	Action: func(c *cli.Context) error {
		if c.Args().Len() != 2 {
			return fmt.Errorf("invalid number of arguments")
		}

		keyName := c.Args().First()
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		newKeyName := c.Args().Get(1)
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

		if _, err = store.GetKey(encNewKeyName); err == nil {
			if !c.Bool("force") {
				return fmt.Errorf("new key already exists")
			}

			if err := store.DeleteKey(encNewKeyName); err != nil {
				return fmt.Errorf("failed to delete key from new key path: %w", err)
			}
		}

		if err := store.SetKey(encNewKeyName, oldKeyPayload); err != nil {
			return fmt.Errorf("failed to set key: %w", err)
		}

		if err := store.DeleteKey(encKeyName); err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}

		fmt.Printf("Key successful moved from %s to %s\n", keyName, newKeyName)

		return nil
	},
}
