package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/vitalvas/gopass/pkg/encryptor"
	"github.com/vitalvas/gopass/pkg/password"
	"github.com/vitalvas/gopass/pkg/vault"
	"github.com/vitalvas/gopass/pkg/vault/filevault"
)

var initCmd = &cli.Command{
	Name:  "init",
	Usage: "Initialize a new password store",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:       "address",
			Usage:      "Store address",
			Value:      fmt.Sprintf("file://%s/.gopass/{{vault}}", os.Getenv("HOME")),
			Required:   true,
			HasBeenSet: true,
		},
		&cli.StringFlag{
			Name:    "encryption-key",
			Usage:   "Encryption key for key (generated if not set)",
			EnvVars: []string{"GOPASS_ENCRYPTION_KEY"},
		},
	},
	Action: func(c *cli.Context) error {
		parsed, err := url.Parse(c.String("address"))
		if err != nil {
			return fmt.Errorf("failed to parse store address: %w", err)
		}

		if parsed.Scheme != "file" {
			return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
		}

		parsed.Path = strings.ReplaceAll(parsed.Path, "{{vault}}", c.String("vault"))

		vaultConfigPath := fmt.Sprintf("%s/.gopass/%s.json", os.Getenv("HOME"), c.String("vault"))

		if _, err := os.Stat(parsed.Path); err == nil {
			return fmt.Errorf("vault already exists: %s", parsed.Path)
		}

		if _, err := os.Stat(fmt.Sprintf("%s.json", parsed.Path)); err == nil {
			return fmt.Errorf("vault config already exists: %s", parsed.Path)
		}

		if err := os.MkdirAll(parsed.Path, 0700); err != nil {
			return fmt.Errorf("failed to create vault directory: %w", err)
		}

		vaultConfig := vault.Config{
			Name:          c.String("vault"),
			Address:       parsed.String(),
			EncryptionKey: c.String("encryption-key"),
		}

		if len(vaultConfig.EncryptionKey) <= 8 {
			vaultConfig.EncryptionKey = password.Generate(32, 0, 8)
		}

		configDir := strings.TrimRight(vaultConfigPath, filepath.Base(vaultConfigPath))
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			log.Printf("creating vault config directory: %s", configDir)

			if err := os.MkdirAll(configDir, 0700); err != nil {
				return fmt.Errorf("failed to create vault config directory: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check vault config directory: %w", err)
		}

		file, err := os.OpenFile(vaultConfigPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to open vault config file: %w", err)
		}

		defer file.Close()

		if err := json.NewEncoder(file).Encode(vaultConfig); err != nil {
			return fmt.Errorf("failed to write vault config: %w", err)
		}

		enc, err := encryptor.NewEncryptor(vaultConfig.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to create encryptor: %w", err)
		}

		store = filevault.New(parsed.Path)

		testEncrypted, err := enc.EncryptKey(vaultConfig.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		if err := store.SetTestKey(testEncrypted); err != nil {
			return fmt.Errorf("failed to set test key: %w", err)
		}

		if resp, err := store.GetTestKey(); err != nil {
			return fmt.Errorf("failed to get test key: %w", err)
		} else if !bytes.Equal(resp, testEncrypted) {
			return fmt.Errorf("test key mismatch")
		}

		return nil
	},
}
