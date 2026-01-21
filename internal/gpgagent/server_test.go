package gpgagent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	socketPath := "/tmp/test-gpg-agent.sock"
	server := NewServer(socketPath)

	assert.NotNil(t, server)
	assert.Equal(t, socketPath, server.SocketPath())
}

func TestServer_StartStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gpgagent-test")
	require.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "S.gpg-agent")
	server := NewServer(socketPath)

	err = server.Start()
	require.NoError(t, err)

	_, err = os.Stat(socketPath)
	assert.NoError(t, err)

	err = server.Stop()
	require.NoError(t, err)

	_, err = os.Stat(socketPath)
	assert.True(t, os.IsNotExist(err))
}

func TestKeyStore_HasKey(t *testing.T) {
	ks := NewKeyStore()

	assert.False(t, ks.HasKey("NONEXISTENT"))
}

func TestKeyStore_ListKeygrips_Empty(t *testing.T) {
	ks := NewKeyStore()

	keygrips := ks.ListKeygrips()
	assert.Empty(t, keygrips)
}
