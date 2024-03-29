package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/password"
)

func init() {
	commands = append(commands, pwgenCmd)
}

var pwgenCmd = &cli.Command{
	Name:  "pwgen",
	Usage: "Generate a random password",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:    "length",
			Aliases: []string{"l"},
			Usage:   "Password length",
			Value:   password.DefaultPasswordLength,
		},
		&cli.IntFlag{
			Name:  "special",
			Usage: "Number of special characters",
			Value: password.DefaultSpecialCharsLength,
		},
		&cli.IntFlag{
			Name:  "numbers",
			Usage: "Number of numbers",
			Value: password.DefaultNumbersLength,
		},
		&cli.IntFlag{
			Name:  "variants",
			Usage: "Number of variants",
			Value: 5,
		},
		&cli.BoolFlag{
			Name:    "string",
			Aliases: []string{"s"},
			Usage:   "String only characters",
			Value:   false,
		},
	},
	Action: func(c *cli.Context) error {
		variants := c.Int("variants")

		for i := 0; i < variants; i++ {
			var (
				length  = c.Int("length")
				special = c.Int("special")
				numbers = c.Int("numbers")
			)

			if c.Bool("string") {
				special = 0
				numbers = 0
			}

			pass := password.Generate(length, special, numbers)
			fmt.Println(pass)
		}
		return nil
	},
}
