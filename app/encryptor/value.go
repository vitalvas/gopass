package encryptor

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

func (e *Encryptor) EncryptValue(key string, text []byte) (string, error) {
	if e.valueAead == nil {
		return "", errors.New("no value encryption key")
	}

	nonce := getNonce(key)

	ciphertext := e.keyAead.Seal(nil, nonce, text, nil)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (e *Encryptor) DecryptValue(key string, text string) ([]byte, error) {
	if e.valueAead == nil {
		return nil, errors.New("no value encryption key")
	}

	nonce := getNonce(key)

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

func getNonce(key string) (data []byte) {
	keyHashed := blake2b.Sum512([]byte(key))

	for i := 0; i < len(keyHashed) && len(data) < chacha20poly1305.NonceSizeX; i++ {
		if i%2 == 0 {
			data = append(data, keyHashed[i])
		}
	}

	return
}
