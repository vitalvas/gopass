package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/blake2b"
)

const (
	mlkemCiphertextSize = 1088
	nonceSize           = 12
)

type Encryptor struct {
	publicKey  *mlkem768.PublicKey
	privateKey *mlkem768.PrivateKey
}

type Keys struct {
	PublicKey  string `json:"pub"`
	PrivateKey string `json:"priv"`
}

func NewEncryptor(keys *Keys) (*Encryptor, error) {
	if keys == nil {
		return nil, errors.New("keys are required")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	publicKey, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	privateKey, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return &Encryptor{
		publicKey:  publicKey.(*mlkem768.PublicKey),
		privateKey: privateKey.(*mlkem768.PrivateKey),
	}, nil
}

func GenerateKeys() (*Keys, error) {
	publicKey, privateKey, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	pubBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	privBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &Keys{
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		PrivateKey: base64.StdEncoding.EncodeToString(privBytes),
	}, nil
}

func (e *Encryptor) KeyID(keyName string) []byte {
	hash := blake2b.Sum256([]byte(keyName))
	return hash[:]
}

func (e *Encryptor) EncryptKey(text string) ([]byte, error) {
	if text == "" {
		return nil, errors.New("empty text")
	}

	return e.encrypt([]byte(text), nil)
}

func (e *Encryptor) DecryptKey(text []byte) (string, error) {
	plaintext, err := e.decrypt(text, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (e *Encryptor) EncryptValue(key string, text []byte) ([]byte, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}

	if len(text) == 0 {
		return nil, errors.New("empty text")
	}

	return e.encrypt(text, []byte(key))
}

func (e *Encryptor) DecryptValue(key string, text []byte) ([]byte, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}

	if text == nil {
		return nil, errors.New("empty text")
	}

	return e.decrypt(text, []byte(key))
}

func (e *Encryptor) encrypt(plaintext, aad []byte) ([]byte, error) {
	ct, ss, err := mlkem768.Scheme().Encapsulate(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	result := make([]byte, 0, len(ct)+nonceSize+len(ciphertext))
	result = append(result, ct...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

func (e *Encryptor) decrypt(data, aad []byte) ([]byte, error) {
	minSize := mlkemCiphertextSize + nonceSize + 16
	if len(data) < minSize {
		return nil, errors.New("ciphertext too short")
	}

	ct := data[:mlkemCiphertextSize]
	nonce := data[mlkemCiphertextSize : mlkemCiphertextSize+nonceSize]
	ciphertext := data[mlkemCiphertextSize+nonceSize:]

	ss, err := mlkem768.Scheme().Decapsulate(e.privateKey, ct)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
