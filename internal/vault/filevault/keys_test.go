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

		// Create test key IDs
		testKeyIDs := [][]byte{
			{0x01, 0x02, 0x03, 0x04},
			{0xaa, 0xbb, 0xcc, 0xdd},
			{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa},
		}

		// Set the keys
		for _, keyID := range testKeyIDs {
			err := v.SetKey(keyID, []byte("enc-key-name"), []byte("enc-value"))
			require.NoError(t, err)
		}

		// List keys
		keys, err := v.ListKeys()
		assert.NoError(t, err)
		assert.Len(t, keys, len(testKeyIDs))

		// Verify all test key IDs are present
		for _, testKeyID := range testKeyIDs {
			found := false
			for _, keyID := range keys {
				if string(keyID) == string(testKeyID) {
					found = true
					break
				}
			}
			assert.True(t, found, "Key %x not found in listed keys", testKeyID)
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
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("encrypted-key-name")
		encValue := []byte("encrypted-value")

		err = v.SetKey(keyID, encKey, encValue)
		require.NoError(t, err)

		retrievedKey, retrievedValue, err := v.GetKey(keyID)
		assert.NoError(t, err)
		assert.Equal(t, encKey, retrievedKey)
		assert.Equal(t, encValue, retrievedValue)
	})

	t.Run("non-existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}

		encKey, encValue, err := v.GetKey(keyID)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
		assert.Nil(t, encKey)
		assert.Nil(t, encValue)
	})

	t.Run("corrupted file content", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}

		// Create corrupted file manually
		filePath, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		fullFilePath := filepath.Join(storagePath, filePath)
		err = os.WriteFile(fullFilePath, []byte("invalid-base64!@#"), 0600)
		require.NoError(t, err)

		encKey, encValue, err := v.GetKey(keyID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "corrupted file")
		assert.Nil(t, encKey)
		assert.Nil(t, encValue)
	})

	t.Run("file stat error", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}

		// Create file with permission issues
		filePath, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		fullFilePath := filepath.Join(storagePath, filePath)
		err = os.WriteFile(fullFilePath, []byte("test"), 0000) // no permissions
		require.NoError(t, err)

		encKey, encValue, err := v.GetKey(keyID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
		assert.Nil(t, encKey)
		assert.Nil(t, encValue)
	})

	t.Run("invalid data format", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}

		// Create file with valid base64 but invalid gzip data
		filePath, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		fullFilePath := filepath.Join(storagePath, filePath)
		// Write valid base64 but not valid gzip data
		err = os.WriteFile(fullFilePath, []byte(base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02})), 0600)
		require.NoError(t, err)

		encKey, encValue, err := v.GetKey(keyID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "corrupted file")
		assert.Nil(t, encKey)
		assert.Nil(t, encValue)
	})
}

func TestSetKey(t *testing.T) {
	t.Run("new key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("encrypted-key-name")
		encValue := []byte("encrypted-value")

		err = v.SetKey(keyID, encKey, encValue)
		assert.NoError(t, err)

		// Verify file was created
		filePath, _ := getKeyPath(keyID)
		fullFilePath := filepath.Join(storagePath, filePath)
		assert.FileExists(t, fullFilePath)

		// Verify content can be read back
		retrievedKey, retrievedValue, err := v.GetKey(keyID)
		require.NoError(t, err)
		assert.Equal(t, encKey, retrievedKey)
		assert.Equal(t, encValue, retrievedValue)
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		oldEncKey := []byte("old-enc-key")
		oldEncValue := []byte("old-enc-value")
		newEncKey := []byte("new-enc-key")
		newEncValue := []byte("new-enc-value")

		// Set initial value
		err = v.SetKey(keyID, oldEncKey, oldEncValue)
		require.NoError(t, err)

		// Overwrite with new value
		err = v.SetKey(keyID, newEncKey, newEncValue)
		assert.NoError(t, err)

		// Verify new value
		retrievedKey, retrievedValue, err := v.GetKey(keyID)
		require.NoError(t, err)
		assert.Equal(t, newEncKey, retrievedKey)
		assert.Equal(t, newEncValue, retrievedValue)
	})

	t.Run("path too long", func(t *testing.T) {
		storagePath := "/" + strings.Repeat("a", 4100) // Create very long path
		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("test")

		err := v.SetKey(keyID, encKey, encValue)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "file path too long")
	})

	t.Run("filename too long", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		// Create very long keyID that results in long filename
		keyID := make([]byte, 200) // This will create base32 string of ~320 chars
		for i := range keyID {
			keyID[i] = 0xff
		}
		encKey := []byte("enc-key")
		encValue := []byte("test")

		err = v.SetKey(keyID, encKey, encValue)
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
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("test")

		err = v.SetKey(keyID, encKey, encValue)
		assert.Error(t, err)

		// Restore permissions for cleanup
		os.Chmod(storagePath, 0755)
	})

	t.Run("file creation failure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("test")

		// Create the directory structure first
		_, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.MkdirAll(fullFileDir, 0700)
		require.NoError(t, err)

		// Make the directory read-only to prevent file creation
		err = os.Chmod(fullFileDir, 0444)
		require.NoError(t, err)

		err = v.SetKey(keyID, encKey, encValue)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write file")

		// Restore permissions for cleanup
		os.Chmod(fullFileDir, 0755)
	})

	t.Run("empty value", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte{}

		err = v.SetKey(keyID, encKey, encValue)
		assert.NoError(t, err)

		retrievedKey, retrievedValue, err := v.GetKey(keyID)
		require.NoError(t, err)
		assert.Equal(t, encKey, retrievedKey)
		assert.Equal(t, encValue, retrievedValue)
	})
}

func TestDeleteKey(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("enc-value")

		// Set key first
		err = v.SetKey(keyID, encKey, encValue)
		require.NoError(t, err)

		// Delete key
		err = v.DeleteKey(keyID)
		assert.NoError(t, err)

		// Verify key is gone
		_, _, err = v.GetKey(keyID)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
	})

	t.Run("non-existing key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}

		err = v.DeleteKey(keyID)
		assert.Error(t, err)
		assert.Equal(t, "key not found", err.Error())
	})

	t.Run("file removal failure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("test")

		// Set key first
		err = v.SetKey(keyID, encKey, encValue)
		require.NoError(t, err)

		// Make directory read-only to prevent file removal
		_, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		err = os.Chmod(fullFileDir, 0444)
		require.NoError(t, err)

		err = v.DeleteKey(keyID)
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
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		encKey := []byte("enc-key")
		encValue := []byte("enc-value")

		// Set key
		err = v.SetKey(keyID, encKey, encValue)
		require.NoError(t, err)

		// Verify directory structure exists
		_, fileDir := getKeyPath(keyID)
		fullFileDir := filepath.Join(storagePath, fileDir)
		assert.DirExists(t, fullFileDir)

		// Delete key
		err = v.DeleteKey(keyID)
		require.NoError(t, err)

		// Verify empty directories are cleaned up
		assert.NoDirExists(t, fullFileDir)
	})
}
