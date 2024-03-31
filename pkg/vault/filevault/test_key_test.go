package filevault

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGetTestKey(t *testing.T) {
	t.Run("non-created key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		if err != nil {
			t.Errorf("Error creating temp dir: %v", err)
		}

		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		key, err := v.GetTestKey()
		if err == nil {
			t.Errorf("Expected GetTestKey() to return an error, got nil")
		}

		if key != nil {
			t.Errorf("Expected GetTestKey() to return an empty string, got %s", key)
		}
	})

	t.Run("created invalid key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		if err != nil {
			t.Errorf("Error creating temp dir: %v", err)
		}

		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		if err != nil {
			t.Errorf("Error creating test key file: %v", err)
		}

		file.WriteString("invalid base64 encoded payload")

		file.Close()

		key, err := v.GetTestKey()
		if err == nil {
			t.Errorf("Expected GetTestKey() to return an error, got nil")
		}

		if key != nil {
			t.Errorf("Expected GetTestKey() to return an empty string, got %s", key)
		}
	})

	t.Run("created valid key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		if err != nil {
			t.Errorf("Error creating temp dir: %v", err)
		}

		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		if err != nil {
			t.Errorf("Error creating test key file: %v", err)
		}

		file.WriteString(base64.RawURLEncoding.EncodeToString([]byte("test")))

		file.Close()

		key, err := v.GetTestKey()
		if err != nil {
			t.Errorf("Expected GetTestKey() to return nil, got %v", err)
		}

		if key == nil {
			t.Errorf("Expected GetTestKey() to return a string, got nil")
		}

		if string(key) != "test" {
			t.Errorf("Expected GetTestKey() to return 'test', got %s", key)
		}
	})
}

func TestSetTestKey(t *testing.T) {
	storagePath, err := os.MkdirTemp("", "gopass")
	if err != nil {
		t.Errorf("Error creating temp dir: %v", err)
	}

	defer os.RemoveAll(storagePath)

	v := New(storagePath)

	err = v.SetTestKey([]byte("test"))
	if err != nil {
		t.Errorf("Error setting test key: %v", err)
	}
}
