package filevault

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
)

const (
	fileExtension = ".txt"
)

func getKeyPath(key []byte) (string, string) {
	fileName := hex.EncodeToString(key)

	keyReverse := make([]byte, len(key))
	copy(keyReverse, key)
	slices.Reverse(keyReverse)

	fileNameReverse := hex.EncodeToString(keyReverse)

	fileDir := filepath.Join(fileNameReverse[0:2], fileNameReverse[2:4])
	filePath := filepath.Join(fileDir, fileName)

	return fmt.Sprintf("%s%s", filePath, fileExtension), fileDir
}
