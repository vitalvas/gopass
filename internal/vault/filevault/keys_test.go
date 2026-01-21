package filevault

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListKeys(t *testing.T) {
	t.Run("empty storage", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keys, err := v.ListKeys()
		assert.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("with valid keys", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		// Create test keys
		testKeys := [][]byte{
			{0x01, 0x02, 0x03, 0x04},
			{0xaa, 0xbb, 0xcc, 0xdd},
			{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa},
		}

		// Set the keys
		for _, key := range testKeys {
			err := v.SetKey(key, []byte("test-value"))
			require.NoError(t, err)
		}

		// List keys
		keys, err := v.ListKeys()
		assert.NoError(t, err)
		assert.Len(t, keys, len(testKeys))

		// Verify all test keys are present
		for _, testKey := range testKeys {
			found := false
			for _, key := range keys {
				if string(key) == string(testKey) {
					found = true
					break
				}
			}
			assert.True(t, found, "Key %x not found in listed keys", testKey)
		}
	})

	t.Run("invalid base32 filename", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		// Create invalid base32 file manually
		invalidDir := filepath.Join(storagePath, "AA", "BB")
		err = os.MkdirAll(invalidDir, 0700)
		require.NoError(t, err)

		invalidFile := filepath.Join(invalidDir, "invalid_base32.txt")
		err = os.WriteFile(invalidFile, []byte("test"), 0600)
		require.NoError(t, err)

		keys, err := v.ListKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode key")
		assert.Nil(t, keys)
	})

	t.Run("glob error", func(t *testing.T) {
		// Use an invalid path pattern that would cause glob to fail
		v := New("invalid[")
		keys, err := v.ListKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list files")
		assert.Nil(t, keys)
	})
}

func TestGetKey(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test-value")

		err = v.SetKey(key, value)
		require.NoError(t, err)

		retrievedValue, err := v.GetKey(key)
		assert.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
	})

	t.Run("non-existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}

		value, err := v.GetKey(key)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
		assert.Nil(t, value)
	})

	t.Run("corrupted file content", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}

		// Create corrupted file manually
		filePath, fileDir := getKeyPath(key)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		fullFilePath := filepath.Join(storagePath, filePath)
		err = os.WriteFile(fullFilePath, []byte("invalid-base64!@#"), 0600)
		require.NoError(t, err)

		value, err := v.GetKey(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode value")
		assert.Nil(t, value)
	})

	t.Run("file stat error", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}

		// Create file with permission issues
		filePath, fileDir := getKeyPath(key)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		fullFilePath := filepath.Join(storagePath, filePath)
		err = os.WriteFile(fullFilePath, []byte("test"), 0000) // no permissions
		require.NoError(t, err)

		value, err := v.GetKey(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
		assert.Nil(t, value)
	})
}

func TestSetKey(t *testing.T) {
	t.Run("new key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test-value")

		err = v.SetKey(key, value)
		assert.NoError(t, err)

		// Verify file was created
		filePath, _ := getKeyPath(key)
		fullFilePath := filepath.Join(storagePath, filePath)
		assert.FileExists(t, fullFilePath)

		// Verify content
		content, err := os.ReadFile(fullFilePath)
		require.NoError(t, err)

		decoded, err := base64.RawURLEncoding.DecodeString(string(content))
		require.NoError(t, err)
		assert.Equal(t, value, decoded)
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		oldValue := []byte("old-value")
		newValue := []byte("new-value")

		// Set initial value
		err = v.SetKey(key, oldValue)
		require.NoError(t, err)

		// Overwrite with new value
		err = v.SetKey(key, newValue)
		assert.NoError(t, err)

		// Verify new value
		retrievedValue, err := v.GetKey(key)
		require.NoError(t, err)
		assert.Equal(t, newValue, retrievedValue)
	})

	t.Run("path too long", func(t *testing.T) {
		storagePath := "/" + strings.Repeat("a", 4100) // Create very long path
		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test")

		err := v.SetKey(key, value)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path too long")
	})

	t.Run("filename too long", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		// Create very long key that results in long filename
		key := make([]byte, 200) // This will create hex string of 400 chars
		for i := range key {
			key[i] = 0xff
		}
		value := []byte("test")

		err = v.SetKey(key, value)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file name too long")
	})

	t.Run("directory creation failure", func(t *testing.T) {
		// Use read-only directory to cause mkdir failure
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Make storage path read-only
		err = os.Chmod(storagePath, 0444)
		require.NoError(t, err)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test")

		err = v.SetKey(key, value)
		assert.Error(t, err)

		// Restore permissions for cleanup
		os.Chmod(storagePath, 0755)
	})

	t.Run("file creation failure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test")

		// Create the directory structure first
		_, fileDir := getKeyPath(key)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		// Make the directory read-only to prevent file creation
		err = os.Chmod(fullFileDir, 0444)
		require.NoError(t, err)

		err = v.SetKey(key, value)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create file")

		// Restore permissions for cleanup
		os.Chmod(fullFileDir, 0755)
	})

	t.Run("empty value", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte{}

		err = v.SetKey(key, value)
		assert.NoError(t, err)

		retrievedValue, err := v.GetKey(key)
		require.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
	})
}

func TestDeleteKey(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test-value")

		// Set key first
		err = v.SetKey(key, value)
		require.NoError(t, err)

		// Delete key
		err = v.DeleteKey(key)
		assert.NoError(t, err)

		// Verify key is gone
		_, err = v.GetKey(key)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
	})

	t.Run("non-existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}

		err = v.DeleteKey(key)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
	})

	t.Run("file removal failure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test")

		// Set key first
		err = v.SetKey(key, value)
		require.NoError(t, err)

		// Make directory read-only to prevent file removal
		_, fileDir := getKeyPath(key)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.Chmod(fullFileDir, 0444)
		require.NoError(t, err)

		err = v.DeleteKey(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete file")

		// Restore permissions for cleanup
		os.Chmod(fullFileDir, 0755)
	})

	t.Run("cleanup after deletion", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		key := []byte{0x01, 0x02, 0x03, 0x04}
		value := []byte("test-value")

		// Set key
		err = v.SetKey(key, value)
		require.NoError(t, err)

		// Verify directory structure exists
		_, fileDir := getKeyPath(key)
		fullFileDir := filepath.Join(storagePath, fileDir)
		assert.DirExists(t, fullFileDir)

		// Delete key
		err = v.DeleteKey(key)
		require.NoError(t, err)

		// Verify empty directories are cleaned up
		assert.NoDirExists(t, fullFileDir)
	})
}
