package filevault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKeyPath(t *testing.T) {
	t.Run("standard key", func(t *testing.T) {
		key := []byte{0x01, 0x02, 0x03, 0x04}
		expectedPath := "aq/bq/aebagba.txt"
		expectedDir := "aq/bq"

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
		expectedPath := "xo/va/vk5q.txt"
		expectedDir := "xo/va"

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
		expectedPath := "ba/dq/aebagbafaydqq.txt"
		expectedDir := "ba/dq"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("all zeros", func(t *testing.T) {
		key := []byte{0x00, 0x00, 0x00, 0x00}
		expectedPath := "aa/aa/aaaaaaa.txt"
		expectedDir := "aa/aa"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("all ones", func(t *testing.T) {
		key := []byte{0xff, 0xff, 0xff, 0xff}
		expectedPath := "77/77/777777y.txt"
		expectedDir := "77/77"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})

	t.Run("asymmetric key", func(t *testing.T) {
		key := []byte{0x12, 0x34}
		expectedPath := "gq/ja/ci2a.txt"
		expectedDir := "gq/ja"

		filePath, fileDir := getKeyPath(key)
		assert.Equal(t, expectedPath, filePath)
		assert.Equal(t, expectedDir, fileDir)
	})
}

func TestFileExtension(t *testing.T) {
	assert.Equal(t, ".txt", fileExtension)
}
