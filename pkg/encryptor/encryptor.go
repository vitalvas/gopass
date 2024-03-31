package encryptor

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor struct {
	keyAead   cipher.AEAD
	valueAead cipher.AEAD
}

func NewEncryptor(keySecret string) (*Encryptor, error) {
	if keySecret == "" {
		return nil, errors.New("no encryption key")
	}

	keySecretBytes := []byte(keySecret)

	keyHash := blake2b.Sum256(keySecretBytes)

	keyAead, err := chacha20poly1305.NewX(keyHash[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}

	valueHash := blake2b.Sum256(
		append(keySecretBytes, keyHash[:]...),
	)

	valueAead, err := chacha20poly1305.NewX(valueHash[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		keyAead:   keyAead,
		valueAead: valueAead,
	}, nil
}
