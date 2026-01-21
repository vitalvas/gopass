package filevault

import (
	"encoding/base32"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	fileExtension = ".txt"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func getKeyPath(key []byte) (string, string) {
	fileName := strings.ToLower(base32Encoding.EncodeToString(key))

	keyReverse := make([]byte, len(key))
	copy(keyReverse, key)
	slices.Reverse(keyReverse)

	fileNameReverse := strings.ToLower(base32Encoding.EncodeToString(keyReverse))

	fileDir := filepath.Join(fileNameReverse[0:2], fileNameReverse[2:4])
	filePath := filepath.Join(fileDir, fileName)

	return fmt.Sprintf("%s%s", filePath, fileExtension), fileDir
}
