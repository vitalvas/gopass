package encryptor

import (
	"encoding/base64"
	"testing"
)

func TestEncryptKey(t *testing.T) {
	enc, err := NewEncryptor(testEncryptKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("invalid keyAead", func(t *testing.T) {
		enc := &Encryptor{}

		if _, err := enc.EncryptKey("test"); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	for _, tc := range []struct {
		name  string
		text  string
		value string
		err   bool
	}{
		{"empty", "", "", true},
		{"short", "short", "HcmRFIQqnnjwcpLz9YU_YW2L4rhC", false},
		{"long", "one/two/there/pass/name", "Ac-bSYT9-W_A88ZmFmgMI5uIXlrY4fG0gUeEZtuwi82VZBEWlV9D", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, err := enc.EncryptKey(tc.text)
			if tc.err && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if encoded := base64.RawURLEncoding.EncodeToString(row); tc.value != encoded {
				t.Fatalf("expected %q, got %q", tc.value, encoded)
			}
		})
	}

}

func TestDecryptKey(t *testing.T) {
	enc, err := NewEncryptor(testEncryptKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("invalid keyAead", func(t *testing.T) {
		enc := &Encryptor{}

		if _, err := enc.DecryptKey(nil); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	for _, tc := range []struct {
		name  string
		text  string
		value string
		err   bool
	}{
		{"empty", "", "", true},
		{"short", "HcmRFIQqnnjwcpLz9YU_YW2L4rhC", "short", false},
		{"long", "Ac-bSYT9-W_A88ZmFmgMI5uIXlrY4fG0gUeEZtuwi82VZBEWlV9D", "one/two/there/pass/name", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := base64.RawURLEncoding.DecodeString(tc.text)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			row, err := enc.DecryptKey(decoded)
			if tc.err && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.value != row {
				t.Fatalf("expected %q, got %q", tc.value, row)
			}
		})
	}
}
