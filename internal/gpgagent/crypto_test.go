package gpgagent

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) (publicKey, privateKey string) {
	t.Helper()

	entity, err := openpgp.NewEntity("Test User", "Test", "test@example.com", nil)
	require.NoError(t, err)

	var pubBuf bytes.Buffer
	pubWriter, err := armor.Encode(&pubBuf, "PGP PUBLIC KEY BLOCK", nil)
	require.NoError(t, err)

	err = entity.Serialize(pubWriter)
	require.NoError(t, err)

	err = pubWriter.Close()
	require.NoError(t, err)

	var privBuf bytes.Buffer
	privWriter, err := armor.Encode(&privBuf, "PGP PRIVATE KEY BLOCK", nil)
	require.NoError(t, err)

	err = entity.SerializePrivate(privWriter, nil)
	require.NoError(t, err)

	err = privWriter.Close()
	require.NoError(t, err)

	return pubBuf.String(), privBuf.String()
}

func TestLoadEntityFromArmor(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)

	t.Run("valid public key", func(t *testing.T) {
		entity, err := LoadEntityFromArmor(publicKey)
		require.NoError(t, err)
		assert.NotNil(t, entity)
		assert.NotNil(t, entity.PrimaryKey)
	})

	t.Run("valid private key", func(t *testing.T) {
		entity, err := LoadEntityFromArmor(privateKey)
		require.NoError(t, err)
		assert.NotNil(t, entity)
		assert.NotNil(t, entity.PrivateKey)
	})

	t.Run("invalid armor", func(t *testing.T) {
		_, err := LoadEntityFromArmor("invalid")
		assert.Error(t, err)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)
	plaintext := []byte("Hello, World!")

	t.Run("armored", func(t *testing.T) {
		encrypted, err := Encrypt(publicKey, plaintext, true)
		require.NoError(t, err)
		assert.Contains(t, string(encrypted), "-----BEGIN PGP MESSAGE-----")

		decrypted, err := Decrypt(privateKey, encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("binary", func(t *testing.T) {
		encrypted, err := Encrypt(publicKey, plaintext, false)
		require.NoError(t, err)
		assert.NotContains(t, string(encrypted), "-----BEGIN PGP MESSAGE-----")

		decrypted, err := Decrypt(privateKey, encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestEncrypt_EmptyData(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)

	encrypted, err := Encrypt(publicKey, []byte{}, true)
	require.NoError(t, err)

	decrypted, err := Decrypt(privateKey, encrypted)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestDecrypt_NoPrivateKey(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)

	encrypted, err := Encrypt(publicKey, []byte("test"), true)
	require.NoError(t, err)

	_, err = Decrypt(privateKey, encrypted)
	require.NoError(t, err)
}

func TestSignVerify(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)
	data := []byte("Data to sign")

	t.Run("armored", func(t *testing.T) {
		signature, err := Sign(privateKey, data, true)
		require.NoError(t, err)
		assert.Contains(t, string(signature), "-----BEGIN PGP SIGNATURE-----")

		err = Verify(publicKey, data, signature)
		require.NoError(t, err)
	})

	t.Run("binary", func(t *testing.T) {
		signature, err := Sign(privateKey, data, false)
		require.NoError(t, err)

		err = Verify(publicKey, data, signature)
		require.NoError(t, err)
	})
}

func TestSign_NoPrivateKey(t *testing.T) {
	publicKey, _ := generateTestKey(t)

	_, err := Sign(publicKey, []byte("test"), true)
	assert.Error(t, err)
}

func TestVerify_InvalidSignature(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)
	data := []byte("Original data")
	wrongData := []byte("Wrong data")

	signature, err := Sign(privateKey, data, true)
	require.NoError(t, err)

	err = Verify(publicKey, wrongData, signature)
	assert.Error(t, err)
}

func TestSign_EmptyData(t *testing.T) {
	publicKey, privateKey := generateTestKey(t)

	signature, err := Sign(privateKey, []byte{}, true)
	require.NoError(t, err)

	err = Verify(publicKey, []byte{}, signature)
	require.NoError(t, err)
}
