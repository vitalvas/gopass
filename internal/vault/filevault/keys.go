package filevault

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (v *Vault) ListKeys() ([][]byte, error) {
	fileList, err := filepath.Glob(filepath.Join(v.storagePath, "*", "*", fmt.Sprintf("*%s", fileExtension)))
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	response := make([][]byte, 0, len(fileList))

	for _, row := range fileList {
		name := strings.TrimSuffix(filepath.Base(row), fileExtension)

		decoded, err := base32Encoding.DecodeString(strings.ToUpper(name))
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}

		response = append(response, decoded)
	}

	return response, nil
}

func (v *Vault) GetKey(keyID []byte) ([]byte, []byte, error) {
	filePath, _ := getKeyPath(keyID)

	fullFilePath := filepath.Join(v.storagePath, filePath)

	if _, err := os.Stat(fullFilePath); os.IsNotExist(err) {
		return nil, nil, errors.New("key not found")
	} else if err != nil {
		return nil, nil, fmt.Errorf("failed to check file: %w", err)
	}

	encoded, err := os.ReadFile(fullFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	data, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, nil, fmt.Errorf("corrupted file: failed to decode: %w", err)
	}

	if len(data) < 4 {
		return nil, nil, errors.New("corrupted file: too short")
	}

	keyLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+keyLen) {
		return nil, nil, errors.New("corrupted file: invalid key length")
	}

	encryptedKey := data[4 : 4+keyLen]
	encryptedValue := data[4+keyLen:]

	return encryptedKey, encryptedValue, nil
}

func (v *Vault) SetKey(keyID []byte, encryptedKey []byte, encryptedValue []byte) error {
	filePath, fileDir := getKeyPath(keyID)

	fullDirPath := filepath.Join(v.storagePath, fileDir)

	if len(fullDirPath) > 4096 {
		return fmt.Errorf("file path too long: %s", fullDirPath)
	}

	if len(filepath.Base(filePath)) > 255 {
		return fmt.Errorf("file name too long: %s", filepath.Base(filePath))
	}

	if _, err := os.Stat(fullDirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(fullDirPath, 0700); err != nil {
			return err
		}
	}

	data := make([]byte, 4+len(encryptedKey)+len(encryptedValue))
	binary.BigEndian.PutUint32(data[:4], uint32(len(encryptedKey)))
	copy(data[4:], encryptedKey)
	copy(data[4+len(encryptedKey):], encryptedValue)

	encoded := base64.RawURLEncoding.EncodeToString(data)

	fullFilePath := filepath.Join(v.storagePath, filePath)

	if err := os.WriteFile(fullFilePath, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func (v *Vault) DeleteKey(keyID []byte) error {
	filePath, _ := getKeyPath(keyID)

	fullFilePath := filepath.Join(v.storagePath, filePath)

	if _, err := os.Stat(fullFilePath); os.IsNotExist(err) {
		return errors.New("key not found")
	}

	if err := os.Remove(fullFilePath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	if err := cleanupStorage(v.storagePath); err != nil {
		return fmt.Errorf("failed to cleanup storage: %w", err)
	}

	return nil
}
