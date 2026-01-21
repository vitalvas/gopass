package passkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCredential(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice@example.com")
	require.NoError(t, err)

	assert.NotEmpty(t, cred.ID)
	assert.NotEmpty(t, cred.PrivateKeyPEM)
	assert.NotEmpty(t, cred.PublicKeyPEM)
	assert.Equal(t, "example.com", cred.RPID)
	assert.Equal(t, "user123", cred.UserID)
	assert.Equal(t, "alice@example.com", cred.UserName)
	assert.Equal(t, uint32(0), cred.SignCount)
	assert.False(t, cred.CreatedAt.IsZero())
}

func TestCredential_GetKeys(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice")
	require.NoError(t, err)

	privateKey, err := cred.GetPrivateKey()
	require.NoError(t, err)
	assert.NotNil(t, privateKey)

	publicKey, err := cred.GetPublicKey()
	require.NoError(t, err)
	assert.NotNil(t, publicKey)

	assert.Equal(t, &privateKey.PublicKey, publicKey)
}

func TestCredential_SignAndVerify(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice")
	require.NoError(t, err)

	challenge := []byte("test challenge data")

	signature, err := cred.Sign(challenge)
	require.NoError(t, err)
	assert.Len(t, signature, 64)
	assert.Equal(t, uint32(1), cred.SignCount)

	valid, err := cred.Verify(challenge, signature)
	require.NoError(t, err)
	assert.True(t, valid)

	valid, err = cred.Verify([]byte("wrong challenge"), signature)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestCredential_SignCount(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice")
	require.NoError(t, err)

	assert.Equal(t, uint32(0), cred.SignCount)

	for i := 1; i <= 5; i++ {
		_, err := cred.Sign([]byte("challenge"))
		require.NoError(t, err)
		assert.Equal(t, uint32(i), cred.SignCount)
	}
}

func TestCredential_PublicKeyBase64(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice")
	require.NoError(t, err)

	pubKeyB64, err := cred.PublicKeyBase64()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyB64)
	assert.Len(t, pubKeyB64, 122)
}

func TestCredential_InvalidSignatureLength(t *testing.T) {
	cred, err := GenerateCredential("example.com", "user123", "alice")
	require.NoError(t, err)

	_, err = cred.Verify([]byte("challenge"), []byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature length")
}
