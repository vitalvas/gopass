package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/internal/otp"
	"github.com/vitalvas/gopass/internal/qrcode"
	"github.com/vitalvas/gopass/internal/vault"
)

var otpCmd = &cobra.Command{
	Use:   "otp",
	Short: "Manage OTP/TOTP secrets",
}

var otpCodeCmd = &cobra.Command{
	Use:     "code <key name>",
	Aliases: []string{"show", "get"},
	Short:   "Generate OTP code for a key",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		keyID := encrypt.KeyID(keyName)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(keyName, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.OTP == nil {
			return fmt.Errorf("key does not contain OTP secret")
		}

		totp := &otp.TOTP{
			Secret: payload.OTP.Secret,
			Digits: payload.OTP.Digits,
			Period: payload.OTP.Period,
		}

		if totp.Digits == 0 {
			totp.Digits = otp.DefaultDigits
		}
		if totp.Period == 0 {
			totp.Period = otp.DefaultPeriod
		}

		code, err := totp.Generate()
		if err != nil {
			return fmt.Errorf("failed to generate OTP: %w", err)
		}

		fmt.Printf("%s (%ds remaining)\n", code, totp.RemainingSeconds())

		return nil
	},
}

var (
	otpInsertForce bool
	otpURIQRCode   bool
)

var otpInsertCmd = &cobra.Command{
	Use:     "insert <key name>",
	Aliases: []string{"add", "set"},
	Short:   "Insert OTP secret for a key",
	Long: `Insert OTP secret for a key.

You can provide either:
- An otpauth:// URI (from QR code)
- A raw base32 secret

Examples:
  gopass otp insert /services/github
  echo "otpauth://totp/GitHub:user?secret=ABCDEFGH&issuer=GitHub" | gopass otp insert /services/github`,
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		keyID := encrypt.KeyID(keyName)

		var existingPayload *vault.Payload

		_, encValue, err := store.GetKey(keyID)
		if err == nil {
			if !otpInsertForce {
				value, err := encrypt.DecryptValue(keyName, encValue)
				if err == nil {
					existingPayload, _ = vault.PayloadUnmarshal(value)
					if existingPayload != nil && existingPayload.OTP != nil {
						return fmt.Errorf("OTP already exists for this key, use --force to overwrite")
					}
				}
			} else {
				value, err := encrypt.DecryptValue(keyName, encValue)
				if err == nil {
					existingPayload, _ = vault.PayloadUnmarshal(value)
				}
			}
		}

		fmt.Print("Enter OTP secret or otpauth:// URI: ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			return fmt.Errorf("OTP secret cannot be empty")
		}

		var otpData *vault.OTP

		if strings.HasPrefix(input, "otpauth://") {
			uri, err := otp.ParseURI(input)
			if err != nil {
				return fmt.Errorf("failed to parse OTP URI: %w", err)
			}

			if uri.Type != "totp" {
				return fmt.Errorf("only TOTP is supported, got: %s", uri.Type)
			}

			otpData = &vault.OTP{
				Secret: uri.Secret,
				Digits: uri.Digits,
				Period: uri.Period,
			}
		} else {
			otpData = &vault.OTP{
				Secret: strings.ToUpper(strings.ReplaceAll(input, " ", "")),
				Digits: otp.DefaultDigits,
				Period: otp.DefaultPeriod,
			}
		}

		totp := &otp.TOTP{
			Secret: otpData.Secret,
			Digits: otpData.Digits,
			Period: otpData.Period,
		}

		if _, err := totp.Generate(); err != nil {
			return fmt.Errorf("invalid OTP secret: %w", err)
		}

		payload := &vault.Payload{
			OTP: otpData,
		}

		if existingPayload != nil {
			payload.Data = existingPayload.Data
		}

		payloadEncoded, err := payload.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		encKeyName, err := encrypt.EncryptKey(keyName)
		if err != nil {
			return fmt.Errorf("failed to encrypt key name: %w", err)
		}

		newEncValue, err := encrypt.EncryptValue(keyName, payloadEncoded)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		if err := store.SetKey(keyID, encKeyName, newEncValue); err != nil {
			return fmt.Errorf("failed to store key: %w", err)
		}

		fmt.Println("OTP secret stored successfully:", keyName)

		return nil
	},
}

var otpURICmd = &cobra.Command{
	Use:     "uri <key name>",
	Short:   "Show OTP URI for a key",
	Args:    cobra.ExactArgs(1),
	PreRunE: loader,
	RunE: func(_ *cobra.Command, args []string) error {
		keyName := args[0]
		if err := vault.ValidateKeyName(keyName); err != nil {
			return err
		}

		keyID := encrypt.KeyID(keyName)

		_, encValue, err := store.GetKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		value, err := encrypt.DecryptValue(keyName, encValue)
		if err != nil {
			return fmt.Errorf("failed to decrypt value: %w", err)
		}

		payload, err := vault.PayloadUnmarshal(value)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if payload.OTP == nil {
			return fmt.Errorf("key does not contain OTP secret")
		}

		digits := payload.OTP.Digits
		if digits == 0 {
			digits = otp.DefaultDigits
		}

		period := payload.OTP.Period
		if period == 0 {
			period = otp.DefaultPeriod
		}

		uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&digits=%d&period=%d",
			keyName, payload.OTP.Secret, digits, period)

		if otpURIQRCode {
			return qrcode.Print(os.Stdout, uri)
		}

		fmt.Println(uri)

		return nil
	},
}

func init() {
	otpInsertCmd.Flags().BoolVarP(&otpInsertForce, "force", "f", false, "Force overwrite existing OTP")
	otpURICmd.Flags().BoolVarP(&otpURIQRCode, "qrcode", "q", false, "Display as QR code")

	otpCmd.AddCommand(otpCodeCmd)
	otpCmd.AddCommand(otpInsertCmd)
	otpCmd.AddCommand(otpURICmd)
}
