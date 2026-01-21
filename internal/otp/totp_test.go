package otp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTP_Generate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		secret   string
		time     time.Time
		expected string
	}{
		{
			name:     "RFC 6238 test vector 1",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			time:     time.Unix(59, 0),
			expected: "287082",
		},
		{
			name:     "RFC 6238 test vector 2",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			time:     time.Unix(1111111109, 0),
			expected: "081804",
		},
		{
			name:     "RFC 6238 test vector 3",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			time:     time.Unix(1234567890, 0),
			expected: "005924",
		},
		{
			name:     "secret with spaces",
			secret:   "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
			time:     time.Unix(59, 0),
			expected: "287082",
		},
		{
			name:     "lowercase secret",
			secret:   "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
			time:     time.Unix(59, 0),
			expected: "287082",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			totp := NewTOTP(tc.secret)
			code, err := totp.GenerateAt(tc.time)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, code)
		})
	}
}

func TestTOTP_Generate_InvalidSecret(t *testing.T) {
	totp := NewTOTP("invalid!@#$%")
	_, err := totp.Generate()
	assert.Error(t, err)
}

func TestTOTP_RemainingSeconds(t *testing.T) {
	totp := NewTOTP("GEZDGNBVGY3TQOJQ")
	remaining := totp.RemainingSeconds()
	assert.GreaterOrEqual(t, remaining, 1)
	assert.LessOrEqual(t, remaining, 30)
}
