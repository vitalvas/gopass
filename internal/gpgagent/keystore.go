package gpgagent

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

type KeyStore struct {
	keys map[string]*openpgp.Entity
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]*openpgp.Entity),
	}
}

func (ks *KeyStore) AddKey(armoredKey string) error {
	block, err := armor.Decode(strings.NewReader(armoredKey))
	if err != nil {
		return fmt.Errorf("failed to decode armor: %w", err)
	}

	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return fmt.Errorf("failed to read key ring: %w", err)
	}

	for _, entity := range entities {
		keyID := fmt.Sprintf("%016X", entity.PrimaryKey.KeyId)
		ks.keys[keyID] = entity

		fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		ks.keys[fingerprint] = entity

		for _, subkey := range entity.Subkeys {
			subkeyID := fmt.Sprintf("%016X", subkey.PublicKey.KeyId)
			ks.keys[subkeyID] = entity
		}
	}

	return nil
}

func (ks *KeyStore) GetKey(keygrip string) (*openpgp.Entity, error) {
	entity, ok := ks.keys[strings.ToUpper(keygrip)]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keygrip)
	}

	return entity, nil
}

func (ks *KeyStore) HasKey(keygrip string) bool {
	_, ok := ks.keys[strings.ToUpper(keygrip)]

	return ok
}

func (ks *KeyStore) ListKeygrips() []string {
	seen := make(map[string]bool)
	var keygrips []string

	for _, entity := range ks.keys {
		keygrip := computeKeygrip(entity.PrimaryKey)
		if !seen[keygrip] {
			seen[keygrip] = true
			keygrips = append(keygrips, keygrip)
		}

		for _, subkey := range entity.Subkeys {
			keygrip := computeKeygrip(subkey.PublicKey)
			if !seen[keygrip] {
				seen[keygrip] = true
				keygrips = append(keygrips, keygrip)
			}
		}
	}

	return keygrips
}

func (ks *KeyStore) GetSigner(keygrip string) (crypto.Signer, error) {
	entity, err := ks.GetKey(keygrip)
	if err != nil {
		return nil, err
	}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}

	signer, ok := entity.PrivateKey.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not support signing")
	}

	return signer, nil
}

func (ks *KeyStore) GetDecrypter(keygrip string) (crypto.Decrypter, error) {
	entity, err := ks.GetKey(keygrip)
	if err != nil {
		return nil, err
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PublicKey.PubKeyAlgo.CanEncrypt() {
			decrypter, ok := subkey.PrivateKey.PrivateKey.(crypto.Decrypter)
			if ok {
				return decrypter, nil
			}
		}
	}

	if entity.PrivateKey != nil {
		decrypter, ok := entity.PrivateKey.PrivateKey.(crypto.Decrypter)
		if ok {
			return decrypter, nil
		}
	}

	return nil, fmt.Errorf("no decryption key available")
}
