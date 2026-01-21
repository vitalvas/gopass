package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/vault"
)

var grepCmd = &cobra.Command{
	Use:     "grep <pattern>",
	Short:   "Search for pattern in stored passwords",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		pattern := strings.ToLower(args[0])

		encKeys, err := store.ListKeys()
		if err != nil {
			return err
		}

		type match struct {
			name string
			line string
		}

		matches := make([]match, 0)

		for _, encKey := range encKeys {
			name, err := encrypt.DecryptKey(encKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt key: %w", err)
			}

			encValue, err := store.GetKey(encKey)
			if err != nil {
				continue
			}

			value, err := encrypt.DecryptValue(name, encValue)
			if err != nil {
				continue
			}

			payload, err := vault.PayloadUnmarshal(value)
			if err != nil {
				continue
			}

			if strings.Contains(strings.ToLower(payload.Data), pattern) {
				matches = append(matches, match{name: name, line: payload.Data})
			}
		}

		if len(matches) == 0 {
			fmt.Println("No matches found for pattern:", args[0])
			return nil
		}

		sort.Slice(matches, func(i, j int) bool {
			return matches[i].name < matches[j].name
		})

		for _, m := range matches {
			fmt.Printf("%s: %s\n", m.name, m.line)
		}

		return nil
	},
}
