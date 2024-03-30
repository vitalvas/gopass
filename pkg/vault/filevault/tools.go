package filevault

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
)

const (
	fileExtension = ".txt"
)

func getKeyPath(key []byte) (string, string) {
	fileName := hex.EncodeToString(key)

	fileDir := filepath.Join(fileName[0:2], fileName[2:4], fileName[4:6])
	filePath := filepath.Join(fileDir, fileName)

	return fmt.Sprintf("%s%s", filePath, fileExtension), fileDir
}
