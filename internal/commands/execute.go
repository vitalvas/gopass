package commands

import (
	"os"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/internal/version"
	"github.com/vitalvas/gopass/pkg/vault"
)

func Execute() error {
	app := &cli.App{
		Name:                 "gopass",
		Usage:                "Simple password manager",
		Version:              version.Version(),
		EnableBashCompletion: true,
		HideHelpCommand:      true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "vault",
				Usage:   "Vault name",
				EnvVars: []string{"GOPASS_VAULT"},
				Value:   "default",
			},
		},
		Commands: []*cli.Command{
			initCmd,
			pwgenCmd,
			generateCmd,
			listCmd,
			getCmd,
			moveCmd,
			deleteCmd,
		},
		Before: func(c *cli.Context) error {
			return vault.ValidateName(c.String("vault"))
		},
	}

	return app.Run(os.Args)
}
