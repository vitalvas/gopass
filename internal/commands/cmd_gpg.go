package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/gpgagent"
	"github.com/vitalvas/gopass/internal/vault"
)

var gpgCmd = &cobra.Command{
	Use:   "gpg",
	Short: "Manage GPG keys stored in the vault",
}

var gpgExportCmd = &cobra.Command{
	Use:     "export <gpg-key-id> <vault-key>",
	Short:   "Export a GPG key from system and store in vault",
	Args:    cobra.ExactArgs(2),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		gpgKeyID := args[0]
		vaultKey := args[1]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		keyID := encrypt.KeyID(vaultKey)

		if _, _, err := store.GetKey(keyID); err == nil {
			if !gpgForce {
				return fmt.Errorf("key already exists: %s (use --force to overwrite)", vaultKey)
			}
		}

		keyInfo, err := getGPGKeyInfo(gpgKeyID)
		if err != nil {
			return fmt.Errorf("failed to get GPG key info: %w", err)
		}

		publicKey, err := exportGPGPublicKey(gpgKeyID)
		if err != nil {
			return fmt.Errorf("failed to export public key: %w", err)
		}

		var privateKey string
		if gpgExportPrivate {
			privateKey, err = exportGPGPrivateKey(gpgKeyID)
			if err != nil {
				return fmt.Errorf("failed to export private key: %w", err)
			}
		}

		payload := &vault.Payload{
			Data: fmt.Sprintf("GPG key: %s", keyInfo.UserID),
			GPGKey: &vault.GPGKey{
				KeyID:       keyInfo.KeyID,
				Fingerprint: keyInfo.Fingerprint,
				UserID:      keyInfo.UserID,
				Email:       keyInfo.Email,
				PublicKey:   publicKey,
				PrivateKey:  privateKey,
				CreatedAt:   time.Now().UTC(),
			},
		}

		data, err := payload.Marshal()
		if err != nil {
			return err
		}

		encKeyName, err := encrypt.EncryptKey(vaultKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encValue, err := encrypt.EncryptValue(vaultKey, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(keyID, encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Printf("GPG key exported to vault: %s\n", vaultKey)
		fmt.Printf("Key ID: %s\n", keyInfo.KeyID)
		fmt.Printf("User ID: %s\n", keyInfo.UserID)

		if gpgExportPrivate {
			fmt.Println("Private key: included")
		} else {
			fmt.Println("Private key: not included (use --private to include)")
		}

		return nil
	},
}

var gpgImportCmd = &cobra.Command{
	Use:     "import <vault-key>",
	Short:   "Import a GPG key from vault to system",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		keyID := encrypt.KeyID(vaultKey)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(vaultKey, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.GPGKey == nil {
			return fmt.Errorf("key does not contain a GPG key")
		}

		gpgKey := payload.GPGKey

		if err := importGPGKey(gpgKey.PublicKey); err != nil {
			return fmt.Errorf("failed to import public key: %w", err)
		}

		fmt.Printf("Public key imported: %s\n", gpgKey.KeyID)

		if gpgKey.PrivateKey != "" && gpgImportPrivate {
			if err := importGPGKey(gpgKey.PrivateKey); err != nil {
				return fmt.Errorf("failed to import private key: %w", err)
			}

			fmt.Println("Private key imported")
		} else if gpgKey.PrivateKey == "" && gpgImportPrivate {
			fmt.Println("Warning: no private key stored in vault")
		}

		return nil
	},
}

var gpgShowCmd = &cobra.Command{
	Use:     "show <vault-key>",
	Short:   "Show GPG key information stored in vault",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		keyID := encrypt.KeyID(vaultKey)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(vaultKey, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.GPGKey == nil {
			return fmt.Errorf("key does not contain a GPG key")
		}

		gpgKey := payload.GPGKey

		fmt.Printf("Key ID: %s\n", gpgKey.KeyID)
		fmt.Printf("Fingerprint: %s\n", gpgKey.Fingerprint)
		fmt.Printf("User ID: %s\n", gpgKey.UserID)

		if gpgKey.Email != "" {
			fmt.Printf("Email: %s\n", gpgKey.Email)
		}

		fmt.Printf("Created At: %s\n", gpgKey.CreatedAt.Format("2006-01-02 15:04:05"))

		if gpgKey.PrivateKey != "" {
			fmt.Println("Private key: stored")
		} else {
			fmt.Println("Private key: not stored")
		}

		if gpgShowPublicKey {
			fmt.Printf("\nPublic Key:\n%s", gpgKey.PublicKey)
		}

		return nil
	},
}

type gpgKeyInfo struct {
	KeyID       string
	Fingerprint string
	UserID      string
	Email       string
}

func getGPGKeyInfo(keyID string) (*gpgKeyInfo, error) {
	cmd := exec.Command("gpg", "--list-keys", "--with-colons", "--keyid-format", "long", keyID)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("key not found: %s", strings.TrimSpace(stderr.String()))
	}

	info := &gpgKeyInfo{}

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")

		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "pub":
			if len(fields) > 4 {
				info.KeyID = fields[4]
			}

		case "fpr":
			if len(fields) > 9 && info.Fingerprint == "" {
				info.Fingerprint = fields[9]
			}

		case "uid":
			if len(fields) > 9 && info.UserID == "" {
				info.UserID = fields[9]

				if start := strings.Index(info.UserID, "<"); start != -1 {
					if end := strings.Index(info.UserID, ">"); end != -1 && end > start {
						info.Email = info.UserID[start+1 : end]
					}
				}
			}
		}
	}

	if info.KeyID == "" {
		return nil, fmt.Errorf("failed to parse key info")
	}

	return info, nil
}

func exportGPGPublicKey(keyID string) (string, error) {
	cmd := exec.Command("gpg", "--armor", "--export", keyID)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to export: %s", strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

func exportGPGPrivateKey(keyID string) (string, error) {
	cmd := exec.Command("gpg", "--armor", "--export-secret-keys", keyID)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to export: %s", strings.TrimSpace(stderr.String()))
	}

	if stdout.Len() == 0 {
		return "", fmt.Errorf("no private key found for %s", keyID)
	}

	return stdout.String(), nil
}

func importGPGKey(armoredKey string) error {
	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = strings.NewReader(armoredKey)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

var gpgAgentCmd = &cobra.Command{
	Use:     "agent [vault-keys...]",
	Short:   "Start GPG agent with keys from vault",
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		socketPath := gpgAgentSocket
		if socketPath == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			socketPath = filepath.Join(homeDir, ".gopass", "S.gpg-agent")
		}

		server := gpgagent.NewServer(socketPath)

		for _, vaultKey := range args {
			if err := vault.ValidateKeyName(vaultKey); err != nil {
				return err
			}

			keyID := encrypt.KeyID(vaultKey)

			_, encValue, err := store.GetKey(keyID)
			if err != nil {
				return fmt.Errorf("failed to get key %s: %w", vaultKey, err)
			}

			value, err := encrypt.DecryptValue(vaultKey, encValue)
			if err != nil {
				return fmt.Errorf("failed to decrypt key %s: %w", vaultKey, err)
			}

			payload, err := vault.PayloadUnmarshal(value)
			if err != nil {
				return fmt.Errorf("failed to unmarshal key %s: %w", vaultKey, err)
			}

			if payload.GPGKey == nil {
				return fmt.Errorf("key %s does not contain a GPG key", vaultKey)
			}

			gpgKey := payload.GPGKey

			if gpgKey.PrivateKey == "" {
				return fmt.Errorf("key %s does not have a private key stored", vaultKey)
			}

			if err := server.AddKey(gpgKey.PrivateKey); err != nil {
				return fmt.Errorf("failed to add key %s: %w", vaultKey, err)
			}

			fmt.Printf("Loaded key: %s (%s)\n", gpgKey.KeyID, gpgKey.UserID)
		}

		if err := server.Start(); err != nil {
			return err
		}

		fmt.Printf("GPG agent started on %s\n", server.SocketPath())
		fmt.Println("Set GPG_AGENT_INFO or use: export GPG_AGENT_INFO=" + server.SocketPath() + ":0:1")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			fmt.Println("\nShutting down...")
			server.Stop()
		}()

		return server.Serve()
	},
}

var gpgEncryptCmd = &cobra.Command{
	Use:     "encrypt <vault-key> [file]",
	Short:   "Encrypt data using a GPG key from vault",
	Args:    cobra.RangeArgs(1, 2),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		gpgKey, err := loadGPGKeyFromVault(vaultKey)
		if err != nil {
			return err
		}

		var input []byte

		if len(args) > 1 {
			input, err = os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
		} else {
			input, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
		}

		encrypted, err := gpgagent.Encrypt(gpgKey.PublicKey, input, gpgArmor)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		if gpgOutputFile != "" {
			if err := os.WriteFile(gpgOutputFile, encrypted, 0600); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			fmt.Printf("Encrypted data written to %s\n", gpgOutputFile)
		} else {
			os.Stdout.Write(encrypted)
		}

		return nil
	},
}

var gpgDecryptCmd = &cobra.Command{
	Use:     "decrypt <vault-key> [file]",
	Short:   "Decrypt data using a GPG key from vault",
	Args:    cobra.RangeArgs(1, 2),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		gpgKey, err := loadGPGKeyFromVault(vaultKey)
		if err != nil {
			return err
		}

		if gpgKey.PrivateKey == "" {
			return fmt.Errorf("no private key stored for %s", vaultKey)
		}

		var input []byte

		if len(args) > 1 {
			input, err = os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
		} else {
			input, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
		}

		decrypted, err := gpgagent.Decrypt(gpgKey.PrivateKey, input)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		if gpgOutputFile != "" {
			if err := os.WriteFile(gpgOutputFile, decrypted, 0600); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			fmt.Printf("Decrypted data written to %s\n", gpgOutputFile)
		} else {
			os.Stdout.Write(decrypted)
		}

		return nil
	},
}

var gpgSignCmd = &cobra.Command{
	Use:     "sign <vault-key> [file]",
	Short:   "Sign data using a GPG key from vault",
	Args:    cobra.RangeArgs(1, 2),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		gpgKey, err := loadGPGKeyFromVault(vaultKey)
		if err != nil {
			return err
		}

		if gpgKey.PrivateKey == "" {
			return fmt.Errorf("no private key stored for %s", vaultKey)
		}

		var input []byte

		if len(args) > 1 {
			input, err = os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
		} else {
			input, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
		}

		signature, err := gpgagent.Sign(gpgKey.PrivateKey, input, gpgArmor)
		if err != nil {
			return fmt.Errorf("signing failed: %w", err)
		}

		if gpgOutputFile != "" {
			if err := os.WriteFile(gpgOutputFile, signature, 0600); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			fmt.Printf("Signature written to %s\n", gpgOutputFile)
		} else {
			os.Stdout.Write(signature)
		}

		return nil
	},
}

var gpgVerifyCmd = &cobra.Command{
	Use:     "verify <vault-key> <signature-file> [data-file]",
	Short:   "Verify a signature using a GPG key from vault",
	Args:    cobra.RangeArgs(2, 3),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		vaultKey := args[0]
		signatureFile := args[1]

		if err := vault.ValidateKeyName(vaultKey); err != nil {
			return err
		}

		gpgKey, err := loadGPGKeyFromVault(vaultKey)
		if err != nil {
			return err
		}

		signature, err := os.ReadFile(signatureFile)
		if err != nil {
			return fmt.Errorf("failed to read signature file: %w", err)
		}

		var data []byte

		if len(args) > 2 {
			data, err = os.ReadFile(args[2])
			if err != nil {
				return fmt.Errorf("failed to read data file: %w", err)
			}
		} else {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
		}

		if err := gpgagent.Verify(gpgKey.PublicKey, data, signature); err != nil {
			return err
		}

		fmt.Println("Signature verified successfully")

		return nil
	},
}

func loadGPGKeyFromVault(vaultKey string) (*vault.GPGKey, error) {
	keyID := encrypt.KeyID(vaultKey)

	_, encValue, err := store.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	value, err := encrypt.DecryptValue(vaultKey, encValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt value: %w", err)
	}

	payload, err := vault.PayloadUnmarshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	if payload.GPGKey == nil {
		return nil, fmt.Errorf("key does not contain a GPG key")
	}

	return payload.GPGKey, nil
}

var (
	gpgForce         bool
	gpgExportPrivate bool
	gpgImportPrivate bool
	gpgShowPublicKey bool
	gpgAgentSocket   string
	gpgArmor         bool
	gpgOutputFile    string
)

func init() {
	gpgExportCmd.Flags().BoolVarP(&gpgForce, "force", "f", false, "Overwrite existing key")
	gpgExportCmd.Flags().BoolVarP(&gpgExportPrivate, "private", "p", false, "Include private key")

	gpgImportCmd.Flags().BoolVarP(&gpgImportPrivate, "private", "p", false, "Import private key if available")

	gpgShowCmd.Flags().BoolVarP(&gpgShowPublicKey, "public-key", "k", false, "Show public key")

	gpgAgentCmd.Flags().StringVarP(&gpgAgentSocket, "socket", "s", "", "Socket path (default: ~/.gopass/S.gpg-agent)")

	gpgEncryptCmd.Flags().BoolVarP(&gpgArmor, "armor", "a", true, "ASCII armor output")
	gpgEncryptCmd.Flags().StringVarP(&gpgOutputFile, "output", "o", "", "Output file (default: stdout)")

	gpgDecryptCmd.Flags().StringVarP(&gpgOutputFile, "output", "o", "", "Output file (default: stdout)")

	gpgSignCmd.Flags().BoolVarP(&gpgArmor, "armor", "a", true, "ASCII armor output")
	gpgSignCmd.Flags().StringVarP(&gpgOutputFile, "output", "o", "", "Output file (default: stdout)")

	gpgCmd.AddCommand(gpgExportCmd)
	gpgCmd.AddCommand(gpgImportCmd)
	gpgCmd.AddCommand(gpgShowCmd)
	gpgCmd.AddCommand(gpgAgentCmd)
	gpgCmd.AddCommand(gpgEncryptCmd)
	gpgCmd.AddCommand(gpgDecryptCmd)
	gpgCmd.AddCommand(gpgSignCmd)
	gpgCmd.AddCommand(gpgVerifyCmd)
}
