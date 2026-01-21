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
		{"short", "short", "kXnNIi5w3UsUFnNERvZ_yPfrgd7K", false},
		{"long", "one/two/there/pass/name", "jX_Hfy44pXYrWztIfvPASZuUFUlnx6j7uWY8gl3-opxJ5jZhkFLT", false},
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
		{"short", "kXnNIi5w3UsUFnNERvZ_yPfrgd7K", "short", false},
		{"long", "jX_Hfy44pXYrWztIfvPASZuUFUlnx6j7uWY8gl3-opxJ5jZhkFLT", "one/two/there/pass/name", false},
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
