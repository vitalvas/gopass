package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Credential struct {
	ID            string    `json:"id"`
	PrivateKeyPEM string    `json:"private_key"`
	PublicKeyPEM  string    `json:"public_key"`
	RPID          string    `json:"rp_id"`
	UserID        string    `json:"user_id"`
	UserName      string    `json:"user_name"`
	SignCount     uint32    `json:"sign_count"`
	CreatedAt     time.Time `json:"created_at"`
}

func GenerateCredential(rpID, userID, userName string) (*Credential, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		return nil, fmt.Errorf("failed to generate credential ID: %w", err)
	}

	return &Credential{
		ID:            base64.RawURLEncoding.EncodeToString(credentialID),
		PrivateKeyPEM: string(privateKeyPEM),
		PublicKeyPEM:  string(publicKeyPEM),
		RPID:          rpID,
		UserID:        userID,
		UserName:      userName,
		SignCount:     0,
		CreatedAt:     time.Now().UTC(),
	}, nil
}

func (c *Credential) GetPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(c.PrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func (c *Credential) GetPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(c.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPub, nil
}

func (c *Credential) Sign(challenge []byte) ([]byte, error) {
	privateKey, err := c.GetPrivateKey()
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(challenge)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	c.SignCount++

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

func (c *Credential) Verify(challenge, signature []byte) (bool, error) {
	if len(signature) != 64 {
		return false, fmt.Errorf("invalid signature length")
	}

	publicKey, err := c.GetPublicKey()
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(challenge)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(publicKey, hash[:], r, s), nil
}

func (c *Credential) PublicKeyBase64() (string, error) {
	block, _ := pem.Decode([]byte(c.PublicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	return base64.RawURLEncoding.EncodeToString(block.Bytes), nil
}
