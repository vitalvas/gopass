package filevault

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

const testKeyName = ".test_key"

func (v *Vault) GetTestKey() ([]byte, error) {
	testKeyPath := filepath.Join(v.storagePath, testKeyName)

	payload, err := os.ReadFile(testKeyPath)
	if err != nil {
		return nil, err
	}

	payloadPlain, err := base64.RawURLEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, err
	}

	return payloadPlain, nil
}

func (v *Vault) SetTestKey(value []byte) error {
	testKeyPath := filepath.Join(v.storagePath, testKeyName)

	file, err := os.Create(testKeyPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encodedValue := base64.RawURLEncoding.EncodeToString(value)

	if _, err := file.Write([]byte(encodedValue)); err != nil {
		return err
	}

	return nil
}
