package encryptor

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func (e *Encryptor) EncryptKey(text string) ([]byte, error) {
	if e.keyAead == nil {
		return nil, errors.New("no key encryption key")
	}

	if text == "" {
		return nil, errors.New("empty text")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)

	ciphertext := e.keyAead.Seal(nil, nonce, []byte(text), nil)

	return ciphertext, nil
}

func (e *Encryptor) DecryptKey(text []byte) (string, error) {
	if e.keyAead == nil {
		return "", errors.New("no key encryption key")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)

	plaintext, err := e.keyAead.Open(nil, nonce, text, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
