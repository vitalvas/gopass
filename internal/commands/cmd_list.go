package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
)

var listCmd = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List of stored keys",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "prefix",
			Aliases: []string{"p"},
			Usage:   "Filter keys by prefix",
		},
	},
	Before: loader,
	Action: func(c *cli.Context) error {
		prefix := c.String("prefix")

		encKeys, err := store.ListKeys()
		if err != nil {
			return err
		}

		names := make([]string, 0, len(encKeys))

		for _, encKey := range encKeys {
			name, err := encrypt.DecryptKey(encKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt key: %w", err)
			}

			names = append(names, name)
		}

		sort.Strings(names)

		for _, row := range names {
			if strings.HasPrefix(row, prefix) {
				fmt.Println(row)
			}
		}

		return nil
	},
}
