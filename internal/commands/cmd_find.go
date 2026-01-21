package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var findCmd = &cobra.Command{
	Use:     "find <pattern>",
	Aliases: []string{"search"},
	Short:   "Search for keys matching a pattern",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		pattern := strings.ToLower(args[0])

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

			if strings.Contains(strings.ToLower(name), pattern) {
				names = append(names, name)
			}
		}

		sort.Strings(names)

		if len(names) == 0 {
			fmt.Println("No keys found matching pattern:", args[0])
			return nil
		}

		for _, name := range names {
			fmt.Println(name)
		}

		return nil
	},
}
