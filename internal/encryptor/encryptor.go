package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/blake2b"
)

type Encryptor struct {
	keyAead cipher.AEAD
}

func NewEncryptor(keySecret string) (*Encryptor, error) {
	if keySecret == "" {
		return nil, errors.New("no encryption key")
	}

	keySecretBytes := []byte(keySecret)

	keyHash := blake2b.Sum256(keySecretBytes)

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	keyAead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		keyAead: keyAead,
	}, nil
}
