package encryptor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeys(t *testing.T) {
	keys, err := GenerateKeys()
	require.NoError(t, err)
	assert.NotEmpty(t, keys.PublicKey)
	assert.NotEmpty(t, keys.PrivateKey)
}

func TestNewEncryptor(t *testing.T) {
	t.Run("valid keys", func(t *testing.T) {
		keys, err := GenerateKeys()
		require.NoError(t, err)

		enc, err := NewEncryptor(keys)
		require.NoError(t, err)
		assert.NotNil(t, enc)
	})

	t.Run("nil keys", func(t *testing.T) {
		_, err := NewEncryptor(nil)
		assert.Error(t, err)
	})

	t.Run("invalid public key", func(t *testing.T) {
		keys := &Keys{
			PublicKey:  "invalid",
			PrivateKey: "aW52YWxpZA==",
		}
		_, err := NewEncryptor(keys)
		assert.Error(t, err)
	})
}

func TestEncryptor_EncryptDecryptKey(t *testing.T) {
	keys, err := GenerateKeys()
	require.NoError(t, err)

	enc, err := NewEncryptor(keys)
	require.NoError(t, err)

	t.Run("roundtrip", func(t *testing.T) {
		original := "/path/to/secret/key"
		encrypted, err := enc.EncryptKey(original)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := enc.DecryptKey(encrypted)
		require.NoError(t, err)
		assert.Equal(t, original, decrypted)
	})

	t.Run("empty text", func(t *testing.T) {
		_, err := enc.EncryptKey("")
		assert.Error(t, err)
	})

	t.Run("different encryptions produce different ciphertexts", func(t *testing.T) {
		original := "/test/key"
		ct1, err := enc.EncryptKey(original)
		require.NoError(t, err)

		ct2, err := enc.EncryptKey(original)
		require.NoError(t, err)

		assert.NotEqual(t, ct1, ct2)
	})
}

func TestEncryptor_EncryptDecryptValue(t *testing.T) {
	keys, err := GenerateKeys()
	require.NoError(t, err)

	enc, err := NewEncryptor(keys)
	require.NoError(t, err)

	t.Run("roundtrip", func(t *testing.T) {
		key := "/path/to/secret"
		original := []byte("super secret password")

		encrypted, err := enc.EncryptValue(key, original)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := enc.DecryptValue(key, encrypted)
		require.NoError(t, err)
		assert.Equal(t, original, decrypted)
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := enc.EncryptValue("", []byte("data"))
		assert.Error(t, err)
	})

	t.Run("empty text", func(t *testing.T) {
		_, err := enc.EncryptValue("/key", []byte{})
		assert.Error(t, err)
	})

	t.Run("wrong key for decryption", func(t *testing.T) {
		key := "/path/to/secret"
		original := []byte("super secret password")

		encrypted, err := enc.EncryptValue(key, original)
		require.NoError(t, err)

		_, err = enc.DecryptValue("/different/key", encrypted)
		assert.Error(t, err)
	})

	t.Run("large data", func(t *testing.T) {
		key := "/test/key"
		original := make([]byte, 1024*1024)
		for i := range original {
			original[i] = byte(i % 256)
		}

		encrypted, err := enc.EncryptValue(key, original)
		require.NoError(t, err)

		decrypted, err := enc.DecryptValue(key, encrypted)
		require.NoError(t, err)
		assert.Equal(t, original, decrypted)
	})
}

func TestEncryptor_CrossEncryptorIsolation(t *testing.T) {
	keys1, err := GenerateKeys()
	require.NoError(t, err)
	enc1, err := NewEncryptor(keys1)
	require.NoError(t, err)

	keys2, err := GenerateKeys()
	require.NoError(t, err)
	enc2, err := NewEncryptor(keys2)
	require.NoError(t, err)

	t.Run("cannot decrypt with different keys", func(t *testing.T) {
		original := "/test/key"
		encrypted, err := enc1.EncryptKey(original)
		require.NoError(t, err)

		_, err = enc2.DecryptKey(encrypted)
		assert.Error(t, err)
	})
}

func TestEncryptor_KeyID(t *testing.T) {
	keys, err := GenerateKeys()
	require.NoError(t, err)

	enc, err := NewEncryptor(keys)
	require.NoError(t, err)

	t.Run("consistent output", func(t *testing.T) {
		keyName := "/path/to/secret"
		id1 := enc.KeyID(keyName)
		id2 := enc.KeyID(keyName)
		assert.Equal(t, id1, id2)
	})

	t.Run("fixed length output", func(t *testing.T) {
		keyName := "/path/to/secret"
		id := enc.KeyID(keyName)
		assert.Len(t, id, 32) // BLAKE2b-256 produces 32 bytes
	})

	t.Run("different inputs produce different IDs", func(t *testing.T) {
		id1 := enc.KeyID("/path/one")
		id2 := enc.KeyID("/path/two")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("different encryptors produce same ID for same key name", func(t *testing.T) {
		keys2, err := GenerateKeys()
		require.NoError(t, err)
		enc2, err := NewEncryptor(keys2)
		require.NoError(t, err)

		keyName := "/same/key"
		id1 := enc.KeyID(keyName)
		id2 := enc2.KeyID(keyName)
		assert.Equal(t, id1, id2)
	})
}
