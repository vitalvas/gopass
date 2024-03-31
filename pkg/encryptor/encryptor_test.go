package encryptor

import "testing"

const (
	testEncryptKey = "t7SxRu9tFGK%Y!cE9PMv#kUR"
)

func TestNewEncryptor(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		err  bool
	}{
		{"+key", testEncryptKey, false},
		{"-key", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEncryptor(tc.key)
			if tc.err && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
