package commands

import (
	"os"

	"github.com/urfave/cli/v2"
)

var commands = []*cli.Command{}

func Execute() error {
	app := &cli.App{
		Name:  "gopass",
		Usage: "Simple password manager",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "vault",
				Usage:   "Vault name",
				EnvVars: []string{"GOPASS_VAULT"},
				Value:   "default",
			},
		},
		Commands: commands,
	}

	return app.Run(os.Args)
}
