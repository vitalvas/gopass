package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURI(t *testing.T) {
	for _, tc := range []struct {
		name      string
		uri       string
		expected  *URI
		expectErr bool
	}{
		{
			name: "basic TOTP URI",
			uri:  "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			expected: &URI{
				Type:   "totp",
				Label:  "Example:alice@example.com",
				Secret: "JBSWY3DPEHPK3PXP",
				Issuer: "Example",
				Digits: 6,
				Period: 30,
			},
		},
		{
			name: "TOTP with custom digits and period",
			uri:  "otpauth://totp/Service?secret=ABCDEFGH&digits=8&period=60",
			expected: &URI{
				Type:   "totp",
				Label:  "Service",
				Secret: "ABCDEFGH",
				Digits: 8,
				Period: 60,
			},
		},
		{
			name: "HOTP URI",
			uri:  "otpauth://hotp/Test?secret=SECRET123",
			expected: &URI{
				Type:   "hotp",
				Label:  "Test",
				Secret: "SECRET123",
				Digits: 6,
				Period: 30,
			},
		},
		{
			name:      "invalid scheme",
			uri:       "https://example.com",
			expectErr: true,
		},
		{
			name:      "missing secret",
			uri:       "otpauth://totp/Test",
			expectErr: true,
		},
		{
			name:      "unsupported type",
			uri:       "otpauth://unknown/Test?secret=ABC",
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseURI(tc.uri)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected.Type, result.Type)
			assert.Equal(t, tc.expected.Label, result.Label)
			assert.Equal(t, tc.expected.Secret, result.Secret)
			assert.Equal(t, tc.expected.Issuer, result.Issuer)
			assert.Equal(t, tc.expected.Digits, result.Digits)
			assert.Equal(t, tc.expected.Period, result.Period)
		})
	}
}

func TestURI_ToTOTP(t *testing.T) {
	uri := &URI{
		Secret: "TESTSECRET",
		Digits: 8,
		Period: 60,
	}

	totp := uri.ToTOTP()
	assert.Equal(t, "TESTSECRET", totp.Secret)
	assert.Equal(t, 8, totp.Digits)
	assert.Equal(t, 60, totp.Period)
}
