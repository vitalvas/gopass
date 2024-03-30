package filevault

import (
	"encoding/base64"
	"encoding/hex"
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

		decoded, err := hex.DecodeString(name)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}

		response = append(response, decoded)
	}

	return response, nil
}

func (v *Vault) GetKey(key []byte) ([]byte, error) {
	filePath, _ := getKeyPath(key)

	fullFilePath := filepath.Join(v.storagePath, filePath)

	if _, err := os.Stat(fullFilePath); os.IsNotExist(err) {
		return nil, errors.New("key not found")
	} else if err != nil {
		return nil, fmt.Errorf("failed to check file: %w", err)
	}

	payload, err := os.ReadFile(fullFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	value, err := base64.RawURLEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to decode value: %w", err)
	}

	return value, nil
}

func (v *Vault) SetKey(key []byte, value []byte) error {
	filePath, fileDir := getKeyPath(key)

	fullFilePath := filepath.Join(v.storagePath, fileDir)

	// check os path length limits
	if len(fullFilePath) > 4096 {
		return fmt.Errorf("file path too long: %s", fullFilePath)
	}

	// check os file name length limits
	if len(filepath.Base(filePath)) > 255 {
		return fmt.Errorf("file name too long: %s", filepath.Base(filePath))
	}

	if _, err := os.Stat(fullFilePath); os.IsNotExist(err) {
		if err := os.MkdirAll(fullFilePath, 0700); err != nil {
			return err
		}
	}

	valueEncoded := base64.RawURLEncoding.EncodeToString(value)

	file, err := os.Create(filepath.Join(v.storagePath, filePath))
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	defer file.Close()

	if _, err := file.WriteString(valueEncoded); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

func (v *Vault) DeleteKey(key []byte) error {
	filePath, fileDir := getKeyPath(key)

	fullFilePath := filepath.Join(v.storagePath, filePath)

	if _, err := os.Stat(fullFilePath); os.IsNotExist(err) {
		return errors.New("key not found")
	}

	if err := os.Remove(fullFilePath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	files, err := os.ReadDir(filepath.Join(v.storagePath, fileDir))
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	if len(files) == 0 {
		if err := os.Remove(filepath.Join(v.storagePath, fileDir)); err != nil {
			return fmt.Errorf("failed to delete directory: %w", err)
		}
	}

	return nil
}
