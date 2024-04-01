package encryptor

import (
	"errors"
)

func (e *Encryptor) EncryptValue(key string, text []byte) ([]byte, error) {
	if e.keyAead == nil {
		return nil, errors.New("no value encryption key")
	}

	if key == "" {
		return nil, errors.New("empty key")
	}

	if text == nil || len(text) == 0 {
		return nil, errors.New("empty text")
	}

	nonce := getNonce(key)

	ciphertext := e.keyAead.Seal(nil, nonce, text, nil)

	return ciphertext, nil
}

func (e *Encryptor) DecryptValue(key string, text []byte) ([]byte, error) {
	if e.keyAead == nil {
		return nil, errors.New("no value encryption key")
	}

	if key == "" {
		return nil, errors.New("empty key")
	}

	if text == nil {
		return nil, errors.New("empty text")
	}

	nonce := getNonce(key)

	plaintext, err := e.keyAead.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
