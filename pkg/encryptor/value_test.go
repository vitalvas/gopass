package encryptor

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptValue(t *testing.T) {
	enc, err := NewEncryptor(testEncryptKey, testEncryptVal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, tc := range []struct {
		name  string
		key   string
		text  string
		value string
		err   bool
	}{
		{"empty-key", "", "", "", true},
		{"empty-text", testEncryptKey, "", "", true},
		{"short", testEncryptKey, "short", "zWV8X161oRP8zFxDOCWvrz7zJ4b9", false},
		{"long", testEncryptKey, "one/two/there/pass/name", "0WN2Al6Chn5c14HrOvOyG7ugkTselat4wvqTL8gLCG8yyid5iD16", false},
		{"very-long", testEncryptKey, strings.Repeat("one/two/there/pass/name", 8), "0WN2Al6Chn5c14HrOvOyG7ugkTselavXfqekznZlO9GWfXXzjCsND5FbAh4MRzMovx87-Y1dg3_mXwTSQ4dBQMzb4rikoYbFhvwLBpMVg7QvKNbUK4Iboe0DJg5SFisi7yeH7v3uEEBbOoL5PXqmxEZtQ0YEooGCxFObqpJ6Bx4kb7LPRT0hFQTuq3QXF12TnPMOFpKad1dUtbcV7U3z60fWEON78dkhGdAQwB01WVwPJmyE6UPqd502FxnSuNixqnWy9kXGUi4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, err := enc.EncryptValue(tc.key, tc.text)
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
	enc, err := NewEncryptor(testEncryptKey, testEncryptVal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, tc := range []struct {
		name  string
		key   string
		text  string
		value string
		err   bool
	}{
		{"empty-key", "", "", "", true},
		{"empty-text", testEncryptKey, "", "", true},
		{"short", testEncryptKey, "zWV8X161oRP8zFxDOCWvrz7zJ4b9", "short", false},
		{"long", testEncryptKey, "0WN2Al6Chn5c14HrOvOyG7ugkTselat4wvqTL8gLCG8yyid5iD16", "one/two/there/pass/name", false},
		{"very-long", testEncryptKey, "0WN2Al6Chn5c14HrOvOyG7ugkTselavXfqekznZlO9GWfXXzjCsND5FbAh4MRzMovx87-Y1dg3_mXwTSQ4dBQMzb4rikoYbFhvwLBpMVg7QvKNbUK4Iboe0DJg5SFisi7yeH7v3uEEBbOoL5PXqmxEZtQ0YEooGCxFObqpJ6Bx4kb7LPRT0hFQTuq3QXF12TnPMOFpKad1dUtbcV7U3z60fWEON78dkhGdAQwB01WVwPJmyE6UPqd502FxnSuNixqnWy9kXGUi4", strings.Repeat("one/two/there/pass/name", 8), false},
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
