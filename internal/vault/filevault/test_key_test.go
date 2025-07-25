package filevault

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTestKey(t *testing.T) {
	t.Run("non-created key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		key, err := v.GetTestKey()
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("created invalid key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		require.NoError(t, err)

		_, err = file.WriteString("invalid base64 encoded payload")
		require.NoError(t, err)
		file.Close()

		key, err := v.GetTestKey()
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("created valid key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		require.NoError(t, err)

		_, err = file.WriteString(base64.RawURLEncoding.EncodeToString([]byte("test")))
		require.NoError(t, err)
		file.Close()

		key, err := v.GetTestKey()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "test", string(key))
	})

	t.Run("empty test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		require.NoError(t, err)

		_, err = file.WriteString(base64.RawURLEncoding.EncodeToString([]byte("")))
		require.NoError(t, err)
		file.Close()

		key, err := v.GetTestKey()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "", string(key))
	})

	t.Run("binary test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		binaryData := []byte{0x00, 0x01, 0xff, 0xaa, 0x55}

		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		require.NoError(t, err)

		_, err = file.WriteString(base64.RawURLEncoding.EncodeToString(binaryData))
		require.NoError(t, err)
		file.Close()

		key, err := v.GetTestKey()
		assert.NoError(t, err)
		assert.Equal(t, binaryData, key)
	})

	t.Run("permission denied", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		// Create file with no read permissions
		file, err := os.Create(filepath.Join(storagePath, testKeyName))
		require.NoError(t, err)
		file.Close()

		err = os.Chmod(filepath.Join(storagePath, testKeyName), 0000)
		require.NoError(t, err)

		key, err := v.GetTestKey()
		assert.Error(t, err)
		assert.Nil(t, key)

		// Restore permissions for cleanup
		os.Chmod(filepath.Join(storagePath, testKeyName), 0644)
	})
}

func TestSetTestKey(t *testing.T) {
	t.Run("set new test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		err = v.SetTestKey([]byte("test"))
		assert.NoError(t, err)

		// Verify key was set correctly
		key, err := v.GetTestKey()
		require.NoError(t, err)
		assert.Equal(t, "test", string(key))
	})

	t.Run("overwrite existing test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		// Set initial key
		err = v.SetTestKey([]byte("initial"))
		require.NoError(t, err)

		// Overwrite with new key
		err = v.SetTestKey([]byte("updated"))
		assert.NoError(t, err)

		// Verify new key
		key, err := v.GetTestKey()
		require.NoError(t, err)
		assert.Equal(t, "updated", string(key))
	})

	t.Run("set empty test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		err = v.SetTestKey([]byte(""))
		assert.NoError(t, err)

		key, err := v.GetTestKey()
		require.NoError(t, err)
		assert.Equal(t, "", string(key))
	})

	t.Run("set binary test key", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		binaryData := []byte{0x00, 0x01, 0xff, 0xaa, 0x55}

		err = v.SetTestKey(binaryData)
		assert.NoError(t, err)

		key, err := v.GetTestKey()
		require.NoError(t, err)
		assert.Equal(t, binaryData, key)
	})

	t.Run("permission denied", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Make storage path read-only
		err = os.Chmod(storagePath, 0444)
		require.NoError(t, err)

		v := New(storagePath)

		err = v.SetTestKey([]byte("test"))
		assert.Error(t, err)

		// Restore permissions for cleanup
		os.Chmod(storagePath, 0755)
	})

	t.Run("write failure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)

		// Create readonly file to cause write failure
		testKeyPath := filepath.Join(storagePath, testKeyName)
		file, err := os.Create(testKeyPath)
		require.NoError(t, err)
		file.Close()

		err = os.Chmod(testKeyPath, 0444)
		require.NoError(t, err)

		// This should fail because file is readonly, but os.Create will truncate it first
		// so we need to create a directory with the same name instead
		err = os.Remove(testKeyPath)
		require.NoError(t, err)

		err = os.Mkdir(testKeyPath, 0755) // Create directory with same name
		require.NoError(t, err)

		err = v.SetTestKey([]byte("test"))
		assert.Error(t, err)
	})
}

func TestTestKeyConcurrentAccess(t *testing.T) {
	storagePath, err := os.MkdirTemp("", "gopass")
	require.NoError(t, err)
	defer os.RemoveAll(storagePath)

	v := New(storagePath)
	numGoroutines := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent SetTestKey operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				value := []byte{byte(id), byte(j)}
				err := v.SetTestKey(value)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify some key exists (last writer wins)
	key, err := v.GetTestKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Len(t, key, 2) // Should be 2 bytes
}

func TestTestKeyName(t *testing.T) {
	assert.Equal(t, ".test_key", testKeyName)
}
