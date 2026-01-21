package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultDigits = 6
	DefaultPeriod = 30
)

type TOTP struct {
	Secret string
	Digits int
	Period int
}

func NewTOTP(secret string) *TOTP {
	return &TOTP{
		Secret: secret,
		Digits: DefaultDigits,
		Period: DefaultPeriod,
	}
}

func (t *TOTP) Generate() (string, error) {
	return t.GenerateAt(time.Now())
}

func (t *TOTP) GenerateAt(at time.Time) (string, error) {
	secret := strings.ToUpper(strings.TrimSpace(t.Secret))
	secret = strings.ReplaceAll(secret, " ", "")

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		secretBytes, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("invalid secret: %w", err)
		}
	}

	counter := uint64(at.Unix()) / uint64(t.Period)

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	digits := t.Digits
	if digits <= 0 {
		digits = DefaultDigits
	}

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	code %= mod

	return fmt.Sprintf("%0*d", digits, code), nil
}

func (t *TOTP) RemainingSeconds() int {
	return t.Period - int(time.Now().Unix()%int64(t.Period))
}
