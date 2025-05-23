package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/password"
	"github.com/vitalvas/gopass/pkg/vault"
)

var generateCmd = &cli.Command{
	Name:      "generate",
	Usage:     "Generate and store a new password",
	ArgsUsage: "<key name>",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
			Usage:   "Force overwrite existing key",
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
