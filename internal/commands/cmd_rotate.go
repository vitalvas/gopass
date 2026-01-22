package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/encryptor"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the encryption keys",
	Long: `Rotate the encryption keys for the vault.

This command will:
1. Generate new ML-KEM-768 encryption keys
2. Decrypt all stored keys with the current keys
3. Re-encrypt all keys with the new keys
4. Update the vault configuration
5. Create a backup of the old configuration

WARNING: Keep a backup of your config file!
If you lose it, you will not be able to access your stored data.`,
	PreRunE: loader,
	RunE: func(_ *cobra.Command, _ []string) error {
		reader := bufio.NewReader(os.Stdin)

		newKeys, err := encryptor.GenerateKeys()
		if err != nil {
			return fmt.Errorf("failed to generate new keys: %w", err)
		}

		newEncryptor, err := encryptor.NewEncryptor(newKeys)
		if err != nil {
			return fmt.Errorf("failed to create new encryptor: %w", err)
		}

		allKeys, err := store.ListKeys()
		if err != nil {
			return fmt.Errorf("failed to list keys: %w", err)
		}

		fmt.Printf("Found %d keys to rotate\n", len(allKeys))

		if !rotateForce {
			fmt.Print("Continue? [y/N]: ")
			confirm, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
			confirm = strings.TrimSpace(strings.ToLower(confirm))

			if confirm != "y" && confirm != "yes" {
				fmt.Println("Aborted")
				return nil
			}
		}

		configPath := fmt.Sprintf("%s/.gopass/%s.json", os.Getenv("HOME"), vaultName)
		backupPath := fmt.Sprintf("%s.backup.%d", configPath, time.Now().Unix())

		configData, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}

		if err := os.WriteFile(backupPath, configData, 0600); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}

		fmt.Printf("Config backup created: %s\n", backupPath)

		rotated := 0
		failed := 0

		for _, keyID := range allKeys {
			encKeyName, encValue, err := store.GetKey(keyID)
			if err != nil {
				fmt.Printf("Warning: failed to get key, skipping: %v\n", err)
				failed++

				continue
			}

			keyName, err := encrypt.DecryptKey(encKeyName)
			if err != nil {
				fmt.Printf("Warning: failed to decrypt key name, skipping: %v\n", err)
				failed++

				continue
			}

			value, err := encrypt.DecryptValue(keyName, encValue)
			if err != nil {
				fmt.Printf("Warning: failed to decrypt value for %s: %v\n", keyName, err)
				failed++

				continue
			}

			newEncKeyName, err := newEncryptor.EncryptKey(keyName)
			if err != nil {
				fmt.Printf("Warning: failed to encrypt key name %s: %v\n", keyName, err)
				failed++

				continue
			}

			newEncValue, err := newEncryptor.EncryptValue(keyName, value)
			if err != nil {
				fmt.Printf("Warning: failed to encrypt value for %s: %v\n", keyName, err)
				failed++

				continue
			}

			if err := store.SetKey(keyID, newEncKeyName, newEncValue); err != nil {
				fmt.Printf("Error: failed to store new key %s: %v\n", keyName, err)
				failed++

				continue
			}

			rotated++
		}

		vaultConfig.Keys = newKeys

		newConfigData, err := json.MarshalIndent(vaultConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		if err := os.WriteFile(configPath, newConfigData, 0600); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}

		testKey := []byte("rotation_test_" + fmt.Sprintf("%d", time.Now().Unix()))
		if err := store.SetTestKey(testKey); err != nil {
			return fmt.Errorf("failed to update test key: %w", err)
		}

		fmt.Printf("\nRotation complete:\n")
		fmt.Printf("  Keys rotated: %d\n", rotated)
		if failed > 0 {
			fmt.Printf("  Keys failed: %d\n", failed)
		}
		fmt.Printf("\nConfig updated with new encryption keys\n")
		fmt.Printf("Backup saved to: %s\n", backupPath)

		return nil
	},
}

var rotateForce bool

func init() {
	rotateCmd.Flags().BoolVarP(&rotateForce, "force", "f", false, "Skip confirmation prompt")
}
