package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/vault"
)

var deleteCmd = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"del", "rm"},
	Usage:     "Delete a stored key",
	ArgsUsage: "<key name>",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
			Usage:   "Force delete key",
		},
	},
	Before: loader,
	Action: func(c *cli.Context) error {
		if c.Args().Len() != 1 {
			return fmt.Errorf("invalid number of arguments")
		}

		keyName := c.Args().First()
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		force := c.Bool("force")
		var confirm string

		if !force {
			fmt.Printf("Are you sure you would like to delete %s? [y/N] ", keyName)

			if _, err := fmt.Scanln(&confirm); err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
		}

		if confirm == "y" || force {
			encKeyName, err := encrypt.EncryptKey(keyName)
			if err != nil {
				return fmt.Errorf("failed to encrypt key name: %w", err)
			}

			if err := store.DeleteKey(encKeyName); err != nil {
				return fmt.Errorf("failed to delete key: %w", err)
			}

			fmt.Println("Key deleted:", keyName)
		} else {
			fmt.Println("Deletion aborted")
		}

		return nil
	},
}
