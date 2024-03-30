package commands

import (
	"fmt"
	"os"

	"github.com/vitalvas/gopass/pkg/vault"
)

var (
	// vaultConfig *vault.Config
	store vault.Vault
)

func init() {
	defer func() {
		if store != nil {
			if err := store.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to close store: %v\n", err)
			}
		}
	}()
}

// func configLoader(c *cli.Context) error {
// 	configPath := fmt.Sprintf("%s/.gopass/%s.json", os.Getenv("HOME"), c.String("vault"))

// 	configFile, err := os.Open(configPath)
// 	if err != nil {
// 		return err
// 	}

// 	defer configFile.Close()

// 	return json.NewDecoder(configFile).Decode(&vaultConfig)
// }
