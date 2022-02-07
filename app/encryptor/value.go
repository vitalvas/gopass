package encryptor

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func (e *Encryptor) EncryptValue(key string, text []byte) (string, error) {
	if e.valueAead == nil {
		return "", errors.New("no value encryption key")
	}

	nonceKey := sha256.Sum256([]byte(key))
	nonce := nonceKey[:chacha20poly1305.NonceSizeX]

	ciphertext := e.keyAead.Seal(nil, nonce, text, nil)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (e *Encryptor) DecryptValue(key string, text string) ([]byte, error) {
	if e.valueAead == nil {
		return nil, errors.New("no value encryption key")
	}

	nonceKey := sha256.Sum256([]byte(key))
	nonce := nonceKey[:chacha20poly1305.NonceSizeX]

	valueBytes, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}

	plaintext, err := e.keyAead.Open(nil, nonce, valueBytes, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
