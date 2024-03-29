package encryptor

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor struct {
	keyAead   cipher.AEAD
	valueAead cipher.AEAD
}

func NewEncryptor(keySecret, valueSecret []byte) (*Encryptor, error) {
	e := &Encryptor{}

	var err error

	if keySecret == nil && valueSecret == nil {
		return nil, errors.New("no encryption keys")
	}

	if keySecret != nil {
		e.keyAead, err = chacha20poly1305.NewX(keySecret)
		if err != nil {
			return nil, err
		}
	}

	if valueSecret != nil {
		e.valueAead, err = chacha20poly1305.NewX(keySecret)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}
