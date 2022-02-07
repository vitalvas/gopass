package encryptor

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func (e *Encryptor) EncryptKey(text string) (string, error) {
	if e.keyAead == nil {
		return "", errors.New("no key encryption key")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)

	ciphertext := e.keyAead.Seal(nil, nonce, []byte(text), nil)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (e *Encryptor) DecryptKey(text string) (string, error) {
	if e.keyAead == nil {
		return "", errors.New("no key encryption key")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)

	keyBytes, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	plaintext, err := e.keyAead.Open(nil, nonce, keyBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
