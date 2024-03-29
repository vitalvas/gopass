package encryptor

import (
	"encoding/base64"
	"testing"
)

func TestGetNonce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   []byte
		value string
	}{
		{"empty", []byte{}, "eAJCWcb9JdKRR-FHiuL3VNIQr1gTZJOw"},
		{"short", []byte("short"), "UKbJnf67dvHrPardMqQoLWlhTh7NsFES"},
		{"long", []byte("one/two/there/pass/name"), "vgX7rdIH6CwDOet5TtrQgS4j67RhldUT"},
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
