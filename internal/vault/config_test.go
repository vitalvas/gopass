package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/gopass/internal/encryptor"
)

func TestConfig(t *testing.T) {
	t.Run("with keys", func(t *testing.T) {
		keys, err := encryptor.GenerateKeys()
		assert.NoError(t, err)

		cfg := &Config{
			Name:    "test",
			Address: "file:///tmp/test",
			Keys:    keys,
		}

		assert.Equal(t, "test", cfg.Name)
		assert.Equal(t, "file:///tmp/test", cfg.Address)
		assert.NotNil(t, cfg.Keys)
	})
}
