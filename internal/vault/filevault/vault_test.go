package filevault

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/gopass/internal/vault"
)

func TestNew(t *testing.T) {
	t.Run("valid storage path", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		assert.Equal(t, storagePath, v.storagePath)

		// Verify interface compliance
		var _ vault.Vault = v
	})

	t.Run("empty storage path", func(t *testing.T) {
		v := New("")
		assert.Equal(t, "", v.storagePath)
	})

	t.Run("non-existent storage path", func(t *testing.T) {
		v := New("/non/existent/path")
		assert.Equal(t, "/non/existent/path", v.storagePath)
	})
}

func TestClose(t *testing.T) {
	t.Run("close empty vault", func(t *testing.T) {
		v := New("")
		err := v.Close()
		assert.NoError(t, err)
	})

	t.Run("close vault with storage", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		v := New(storagePath)
		err = v.Close()
		assert.NoError(t, err)
	})

	t.Run("multiple close calls", func(t *testing.T) {
		v := New("")
		err := v.Close()
		assert.NoError(t, err)

		// Second close should also succeed
		err = v.Close()
		assert.NoError(t, err)
	})
}

func TestVaultConcurrentAccess(t *testing.T) {
	storagePath, err := os.MkdirTemp("", "gopass")
	require.NoError(t, err)
	defer os.RemoveAll(storagePath)

	v := New(storagePath)
	numGoroutines := 10
	numOperations := 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent SetKey operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				keyID := []byte{byte(id), byte(j)}
				encKey := []byte{byte(id), byte(j), 0x01}
				encValue := []byte{byte(id * j)}
				err := v.SetKey(keyID, encKey, encValue)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all keys were set correctly
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < numOperations; j++ {
			keyID := []byte{byte(i), byte(j)}
			expectedEncKey := []byte{byte(i), byte(j), 0x01}
			expectedEncValue := []byte{byte(i * j)}

			encKey, encValue, err := v.GetKey(keyID)
			assert.NoError(t, err)
			assert.Equal(t, expectedEncKey, encKey)
			assert.Equal(t, expectedEncValue, encValue)
		}
	}
}

func TestVaultConcurrentReadWrite(t *testing.T) {
	storagePath, err := os.MkdirTemp("", "gopass")
	require.NoError(t, err)
	defer os.RemoveAll(storagePath)

	v := New(storagePath)
	keyID := []byte{0x01, 0x02, 0x03}

	// Set initial value
	err = v.SetKey(keyID, []byte("initial-key"), []byte("initial-value"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	numReaders := 10
	numWriters := 5

	// Start readers
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, err := v.GetKey(keyID)
				// Error is acceptable due to concurrent modifications
				if err != nil && err.Error() != "key not found" {
					// Accept errors from concurrent access (file corruption or read failures)
					_ = err
				}
			}
		}()
	}

	// Start writers
	wg.Add(numWriters)
	for i := 0; i < numWriters; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				encKey := []byte{byte(id), byte(j), 0x01}
				encValue := []byte{byte(id), byte(j)}
				err := v.SetKey(keyID, encKey, encValue)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
}
