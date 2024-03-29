package encryptor

import "testing"

const (
	testEncryptKey = "t7SxRu9tFGK%Y!cE9PMv#kUR"
	testEncryptVal = "UzhGnM9pJQ_wrYZc*DUv69*q"
)

func TestNewEncryptor(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		val  string
		err  bool
	}{
		{"+key;+val", testEncryptKey, testEncryptVal, false},
		{"-key;+val", "", testEncryptVal, true},
		{"+key;-val", testEncryptKey, "", false},
		{"-key;-val", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEncryptor(tc.key, tc.val)
			if tc.err && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
