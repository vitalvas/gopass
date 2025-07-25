package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/encryptor"
	"github.com/vitalvas/gopass/internal/vault"
	"github.com/vitalvas/gopass/internal/vault/filevault"
)

var (
	vaultConfig *vault.Config
	store       vault.Vault
	encrypt     *encryptor.Encryptor
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

func configLoader(_ *cobra.Command, _ []string) error {
	configPath := fmt.Sprintf("%s/.gopass/%s.json", os.Getenv("HOME"), vaultName)

	configFile, err := os.Open(configPath)
	if err != nil {
		return err
	}

	defer configFile.Close()

	return json.NewDecoder(configFile).Decode(&vaultConfig)
}

func vaultLoader(_ *cobra.Command, _ []string) error {
	parsed, err := url.Parse(vaultConfig.Address)
	if err != nil {
		return fmt.Errorf("failed to parse vault address: %w", err)
	}

	switch parsed.Scheme {
	case "file":
		store = filevault.New(parsed.Path)

		if resp, err := store.GetTestKey(); err != nil {
			return fmt.Errorf("failed to get test key: %w", err)
		} else if resp == nil {
			return fmt.Errorf("failed to get test key: response is nil")
		}

	default:
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	return nil
}

func encryptLoader(_ *cobra.Command, _ []string) error {
	var err error
	encrypt, err = encryptor.NewEncryptor(vaultConfig.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	return nil
}

func loader(cmd *cobra.Command, args []string) error {
	if err := configLoader(cmd, args); err != nil {
		return err
	}

	if err := encryptLoader(cmd, args); err != nil {
		return err
	}

	return vaultLoader(cmd, args)
}
