package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/encryptor"
	"github.com/vitalvas/gopass/pkg/vault"
	"github.com/vitalvas/gopass/pkg/vault/filevault"
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

func configLoader(c *cli.Context) error {
	configPath := fmt.Sprintf("%s/.gopass/%s.json", os.Getenv("HOME"), c.String("vault"))

	configFile, err := os.Open(configPath)
	if err != nil {
		return err
	}

	defer configFile.Close()

	return json.NewDecoder(configFile).Decode(&vaultConfig)
}

func vaultLoader(_ *cli.Context) error {
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

func encryptLoader(_ *cli.Context) error {
	var err error
	encrypt, err = encryptor.NewEncryptor(vaultConfig.EncryptionKey, vaultConfig.EncryptionValue)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	return nil
}

func loader(c *cli.Context) error {
	if err := configLoader(c); err != nil {
		return err
	}

	if err := encryptLoader(c); err != nil {
		return err
	}

	return vaultLoader(c)
}
