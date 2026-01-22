package commands

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/passkey"
	"github.com/vitalvas/gopass/internal/vault"
)

var passkeyCmd = &cobra.Command{
	Use:   "passkey",
	Short: "Manage passkey credentials",
}

var passkeyCreateCmd = &cobra.Command{
	Use:     "create <key>",
	Short:   "Create a new passkey credential",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		key := args[0]

		if err := vault.ValidateKeyName(key); err != nil {
			return err
		}

		keyID := encrypt.KeyID(key)

		if _, _, err := store.GetKey(keyID); err == nil {
			if !passkeyForce {
				return fmt.Errorf("key already exists: %s (use --force to overwrite)", key)
			}
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter RPID (e.g., example.com): ")
		rpID, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		rpID = strings.TrimSpace(rpID)

		if rpID == "" {
			return fmt.Errorf("RPID is required")
		}

		fmt.Print("Enter User ID: ")
		userID, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		userID = strings.TrimSpace(userID)

		if userID == "" {
			return fmt.Errorf("user ID is required")
		}

		fmt.Print("Enter User Name: ")
		userName, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		userName = strings.TrimSpace(userName)

		if userName == "" {
			return fmt.Errorf("user name is required")
		}

		cred, err := passkey.GenerateCredential(rpID, userID, userName)
		if err != nil {
			return err
		}

		payload := &vault.Payload{
			Data: fmt.Sprintf("Passkey for %s", rpID),
			Passkey: &vault.Passkey{
				ID:            cred.ID,
				PrivateKeyPEM: cred.PrivateKeyPEM,
				PublicKeyPEM:  cred.PublicKeyPEM,
				RPID:          cred.RPID,
				UserID:        cred.UserID,
				UserName:      cred.UserName,
				SignCount:     cred.SignCount,
				CreatedAt:     cred.CreatedAt,
			},
		}

		data, err := payload.Marshal()
		if err != nil {
			return err
		}

		encKeyName, err := encrypt.EncryptKey(key)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encValue, err := encrypt.EncryptValue(key, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(keyID, encKeyName, encValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Printf("Passkey created for %s\n", rpID)
		fmt.Printf("Credential ID: %s\n", cred.ID)

		return nil
	},
}

var passkeyShowCmd = &cobra.Command{
	Use:     "show <key>",
	Short:   "Show passkey credential information",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		key := args[0]

		if err := vault.ValidateKeyName(key); err != nil {
			return err
		}

		keyID := encrypt.KeyID(key)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(key, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.Passkey == nil {
			return fmt.Errorf("key does not contain a passkey")
		}

		pk := payload.Passkey

		fmt.Printf("Credential ID: %s\n", pk.ID)
		fmt.Printf("RPID: %s\n", pk.RPID)
		fmt.Printf("User ID: %s\n", pk.UserID)
		fmt.Printf("User Name: %s\n", pk.UserName)
		fmt.Printf("Sign Count: %d\n", pk.SignCount)
		fmt.Printf("Created At: %s\n", pk.CreatedAt.Format("2006-01-02 15:04:05"))

		if passkeyShowPublicKey {
			fmt.Printf("\nPublic Key:\n%s", pk.PublicKeyPEM)
		}

		return nil
	},
}

var passkeySignCmd = &cobra.Command{
	Use:     "sign <key>",
	Short:   "Sign a challenge with the passkey",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		key := args[0]

		if err := vault.ValidateKeyName(key); err != nil {
			return err
		}

		keyID := encrypt.KeyID(key)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(key, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.Passkey == nil {
			return fmt.Errorf("key does not contain a passkey")
		}

		pk := payload.Passkey

		var challenge string
		if passkeyChallenge != "" {
			challenge = passkeyChallenge
		} else {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter challenge (base64): ")
			challenge, err = reader.ReadString('\n')
			if err != nil {
				return err
			}
			challenge = strings.TrimSpace(challenge)
		}

		if challenge == "" {
			return fmt.Errorf("challenge is required")
		}

		challengeBytes, err := base64.RawURLEncoding.DecodeString(challenge)
		if err != nil {
			challengeBytes, err = base64.StdEncoding.DecodeString(challenge)
			if err != nil {
				return fmt.Errorf("invalid challenge encoding: %w", err)
			}
		}

		cred := &passkey.Credential{
			ID:            pk.ID,
			PrivateKeyPEM: pk.PrivateKeyPEM,
			PublicKeyPEM:  pk.PublicKeyPEM,
			RPID:          pk.RPID,
			UserID:        pk.UserID,
			UserName:      pk.UserName,
			SignCount:     pk.SignCount,
			CreatedAt:     pk.CreatedAt,
		}

		signature, err := cred.Sign(challengeBytes)
		if err != nil {
			return err
		}

		payload.Passkey.SignCount = cred.SignCount
		updatedData, err := payload.Marshal()
		if err != nil {
			return err
		}

		encKeyName, err := encrypt.EncryptKey(key)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		encUpdatedValue, err := encrypt.EncryptValue(key, updatedData)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(keyID, encKeyName, encUpdatedValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Printf("Signature: %s\n", base64.RawURLEncoding.EncodeToString(signature))
		fmt.Printf("Sign Count: %d\n", cred.SignCount)

		return nil
	},
}

var (
	passkeyForce         bool
	passkeyShowPublicKey bool
	passkeyChallenge     string
)

func init() {
	passkeyCreateCmd.Flags().BoolVarP(&passkeyForce, "force", "f", false, "Overwrite existing key")

	passkeyShowCmd.Flags().BoolVarP(&passkeyShowPublicKey, "public-key", "p", false, "Show public key")

	passkeySignCmd.Flags().StringVarP(&passkeyChallenge, "challenge", "c", "", "Challenge to sign (base64)")

	passkeyCmd.AddCommand(passkeyCreateCmd)
	passkeyCmd.AddCommand(passkeyShowCmd)
	passkeyCmd.AddCommand(passkeySignCmd)
}
