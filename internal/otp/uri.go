package otp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type URI struct {
	Type      string
	Label     string
	Secret    string
	Issuer    string
	Algorithm string
	Digits    int
	Period    int
}

func ParseURI(uri string) (*URI, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	if parsed.Scheme != "otpauth" {
		return nil, fmt.Errorf("invalid scheme: %s (expected otpauth)", parsed.Scheme)
	}

	otpType := parsed.Host
	if otpType != "totp" && otpType != "hotp" {
		return nil, fmt.Errorf("unsupported OTP type: %s", otpType)
	}

	label := strings.TrimPrefix(parsed.Path, "/")
	label, _ = url.PathUnescape(label)

	params := parsed.Query()

	secret := params.Get("secret")
	if secret == "" {
		return nil, fmt.Errorf("missing secret parameter")
	}

	result := &URI{
		Type:      otpType,
		Label:     label,
		Secret:    secret,
		Issuer:    params.Get("issuer"),
		Algorithm: params.Get("algorithm"),
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
	}

	if d := params.Get("digits"); d != "" {
		digits, err := strconv.Atoi(d)
		if err == nil && digits > 0 {
			result.Digits = digits
		}
	}

	if p := params.Get("period"); p != "" {
		period, err := strconv.Atoi(p)
		if err == nil && period > 0 {
			result.Period = period
		}
	}

	return result, nil
}

func (u *URI) ToTOTP() *TOTP {
	return &TOTP{
		Secret: u.Secret,
		Digits: u.Digits,
		Period: u.Period,
	}
}
