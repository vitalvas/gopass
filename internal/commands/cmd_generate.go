package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/password"
	"github.com/vitalvas/gopass/pkg/vault"
)

func init() {
	commands = append(commands, generateCmd)
}

var generateCmd = &cli.Command{
	Name:  "generate",
	Usage: "Generate and store a new password",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Aliases:  []string{"n"},
			Usage:    "Name of the password",
			Required: true,
			Action: func(_ *cli.Context, name string) error {
				if err := vault.ValidateKeyName(name); err != nil {
					return err
				}

				return nil
			},
		},
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Force overwrite existing key",
		},
	},
	Before: loader,
	Action: func(c *cli.Context) error {
		keyName := c.String("name")
		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		if _, err := store.GetKey(encKeyName); err == nil {
			if !c.Bool("force") {
				return fmt.Errorf("key already exists, use --force to overwrite")
			}
		}
		pass := password.Generate(password.DefaultLength, password.DefaultLength, password.DefaultLength)

		encValue, err := encrypt.EncryptValue(keyName, pass)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Println("Password generated and stored successfully")

		return nil
	},
}
