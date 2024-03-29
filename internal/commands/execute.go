package commands

import (
	"os"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/internal/version"
)

var commands = []*cli.Command{}

func Execute() error {
	app := &cli.App{
		Name:    "gopass",
		Usage:   "Simple password manager",
		Version: version.Version(),
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
