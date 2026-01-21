package qrcode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	t.Run("simple text", func(t *testing.T) {
		output, err := Generate("hello")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "\u2588")
	})

	t.Run("url", func(t *testing.T) {
		output, err := Generate("https://example.com")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("otp uri", func(t *testing.T) {
		output, err := Generate("otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := Generate("")
		assert.Error(t, err)
	})
}

func TestPrint(t *testing.T) {
	var buf bytes.Buffer

	err := Print(&buf, "test content")
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.True(t, strings.HasSuffix(output, "\n"))
}

func TestGetPixel(t *testing.T) {
	bitmap := [][]bool{
		{true, false, true},
		{false, true, false},
		{true, true, false},
	}

	t.Run("valid coordinates", func(t *testing.T) {
		assert.True(t, getPixel(bitmap, 0, 0, 3))
		assert.False(t, getPixel(bitmap, 1, 0, 3))
		assert.True(t, getPixel(bitmap, 1, 1, 3))
	})

	t.Run("out of bounds", func(t *testing.T) {
		assert.False(t, getPixel(bitmap, -1, 0, 3))
		assert.False(t, getPixel(bitmap, 0, -1, 3))
		assert.False(t, getPixel(bitmap, 3, 0, 3))
		assert.False(t, getPixel(bitmap, 0, 3, 3))
	})
}
