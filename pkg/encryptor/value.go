package encryptor

import (
	"errors"
)

func (e *Encryptor) EncryptValue(key []byte, text string) ([]byte, error) {
	if e.valueAead == nil {
		return nil, errors.New("no value encryption key")
	}

	if text == "" {
		return nil, errors.New("empty text")
	}

	nonce := getNonce(key)

	ciphertext := e.keyAead.Seal(nil, nonce, []byte(text), nil)

	return ciphertext, nil
}

func (e *Encryptor) DecryptValue(key []byte, text []byte) ([]byte, error) {
	if e.valueAead == nil {
		return nil, errors.New("no value encryption key")
	}

	nonce := getNonce(key)

	plaintext, err := e.keyAead.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
