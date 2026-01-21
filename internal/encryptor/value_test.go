package encryptor

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptValue(t *testing.T) {
	enc, err := NewEncryptor(testEncryptKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("invalid keyAead", func(t *testing.T) {
		enc := &Encryptor{}

		if _, err := enc.EncryptValue("test", []byte("test")); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	for _, tc := range []struct {
		name  string
		key   string
		text  string
		value string
		err   bool
	}{
		{"empty-key", "", "", "", true},
		{"empty-text", testEncryptKey, "", "", true},
		{"short", testEncryptKey, "short", "00fIUALIK0h2xrEkRn8cAXBPuhIp", false},
		{"long", testEncryptKey, "one/two/there/pass/name", "z0HCDQLFpNoRSDEz2pxZdf8-ujPXRiGPQY1h26yxzdLRGKdNdgSx", false},
		{"very-long", testEncryptKey, strings.Repeat("one/two/there/pass/name", 8), "z0HCDQLFpNoRSDEz2pxZdf8-ujPXRiETxnZJMaXwxogCH2TVPmB68KwkB4PLCJrUJwzEVsvYa00gaxroqFMAJ95l2GLNXBAg4RjgBc4o4U4H7OJ42YlEKZ0dEFaoIbf1mU_Y28xisRkgWdNDVmd7n3DYMMIDB5VBNQU9t1j4T0goK9-Y8FJEBWaL9msyE_4OmFzawsAMS_izAsT-SlScD6UpzqRFeJLGiCGdslRyfqnA6STyUWwKeQTMIu7mZVfeSKQsSIliF2E", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, err := enc.EncryptValue(tc.key, []byte(tc.text))
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

func TestDecryptValue(t *testing.T) {
	enc, err := NewEncryptor(testEncryptKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("invalid keyAead", func(t *testing.T) {
		enc := &Encryptor{}

		if _, err := enc.DecryptValue("test", nil); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	for _, tc := range []struct {
		name  string
		key   string
		text  string
		value string
		err   bool
	}{
		{"empty-key", "", "", "", true},
		{"empty-text", testEncryptKey, "", "", true},
		{"short", testEncryptKey, "00fIUALIK0h2xrEkRn8cAXBPuhIp", "short", false},
		{"long", testEncryptKey, "z0HCDQLFpNoRSDEz2pxZdf8-ujPXRiGPQY1h26yxzdLRGKdNdgSx", "one/two/there/pass/name", false},
		{"very-long", testEncryptKey, "z0HCDQLFpNoRSDEz2pxZdf8-ujPXRiETxnZJMaXwxogCH2TVPmB68KwkB4PLCJrUJwzEVsvYa00gaxroqFMAJ95l2GLNXBAg4RjgBc4o4U4H7OJ42YlEKZ0dEFaoIbf1mU_Y28xisRkgWdNDVmd7n3DYMMIDB5VBNQU9t1j4T0goK9-Y8FJEBWaL9msyE_4OmFzawsAMS_izAsT-SlScD6UpzqRFeJLGiCGdslRyfqnA6STyUWwKeQTMIu7mZVfeSKQsSIliF2E", strings.Repeat("one/two/there/pass/name", 8), false},
		{"invalid-text", testEncryptKey, "invalid", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				decoded []byte
				err     error
			)

			if !tc.err {
				decoded, err = base64.RawURLEncoding.DecodeString(tc.text)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			row, err := enc.DecryptValue(tc.key, decoded)
			if tc.err && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.value != string(row) {
				t.Fatalf("expected %q, got %q", tc.value, string(row))
			}
		})
	}
}
