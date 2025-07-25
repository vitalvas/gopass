package filevault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKeyPath(t *testing.T) {
	t.Run("standard key", func(t *testing.T) {
		key := []byte{0x01, 0x02, 0x03, 0x04}
		expectedPath := "04/03/01020304.txt"
		expectedDir := "04/03"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("single byte key", func(t *testing.T) {
		key := []byte{0xff}
		// This will panic due to slice bounds out of range in the current implementation
		// The function expects at least 2 bytes
		assert.Panics(t, func() {
			getKeyPath(key)
		})
	})

	t.Run("two byte key", func(t *testing.T) {
		key := []byte{0xaa, 0xbb}
		expectedPath := "bb/aa/aabb.txt" // reversed is bbaa
		expectedDir := "bb/aa"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("empty key", func(t *testing.T) {
		key := []byte{}
		// This will panic due to slice bounds out of range in the current implementation
		assert.Panics(t, func() {
			getKeyPath(key)
		})
	})

	t.Run("long key", func(t *testing.T) {
		key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		// Original: 0102030405060708
		// Reversed: 0807060504030201
		expectedPath := "08/07/0102030405060708.txt"
		expectedDir := "08/07"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("all zeros", func(t *testing.T) {
		key := []byte{0x00, 0x00, 0x00, 0x00}
		expectedPath := "00/00/00000000.txt"
		expectedDir := "00/00"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("all ones", func(t *testing.T) {
		key := []byte{0xff, 0xff, 0xff, 0xff}
		expectedPath := "ff/ff/ffffffff.txt"
		expectedDir := "ff/ff"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("asymmetric key", func(t *testing.T) {
		key := []byte{0x12, 0x34}
		// Original: 1234
		// Reversed: 3412
		expectedPath := "34/12/1234.txt"
		expectedDir := "34/12"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})
}

func TestFileExtension(t *testing.T) {
	assert.Equal(t, ".txt", fileExtension)
}
