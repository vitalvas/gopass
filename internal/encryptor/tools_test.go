package encryptor

import (
	"encoding/base64"
	"testing"
)

func TestGetNonce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		value string
	}{
		{"empty", "", "DldRwCblQ7Loqy6w"},
		{"short", "short", "nTk4IOnFS3HX-NLn"},
		{"long", "one/two/there/pass/name", "TdVkIjJdkxwf0q-D"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := getNonce(tc.key)

			nonceStr := base64.RawURLEncoding.EncodeToString(nonce)

			if nonceStr != tc.value {
				t.Fatalf("expected %q, got %q", tc.value, nonceStr)
			}
		})
	}
}
