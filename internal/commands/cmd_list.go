package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var listPrefix string

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List of stored keys",
	PreRunE: loader,
	RunE: func(_ *cobra.Command, _ []string) error {
		keyIDs, err := store.ListKeys()
		if err != nil {
			return err
		}

		names := make([]string, 0, len(keyIDs))

		for _, keyID := range keyIDs {
			encKey, _, err := store.GetKey(keyID)
			if err != nil {
				return fmt.Errorf("failed to get key: %w", err)
			}

			name, err := encrypt.DecryptKey(encKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt key: %w", err)
			}

			names = append(names, name)
		}

		sort.Strings(names)

		for _, row := range names {
			if strings.HasPrefix(row, listPrefix) {
				fmt.Println(row)
			}
		}

		return nil
	},
}

func init() {
	listCmd.Flags().StringVarP(&listPrefix, "prefix", "p", "", "Filter keys by prefix")
}
