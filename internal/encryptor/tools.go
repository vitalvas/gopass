package encryptor

import (
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

func getNonce(key string) []byte {
	keyHashed := blake2b.Sum512([]byte(key))

	var data []byte

	for i := 0; i < len(keyHashed) && len(data) < chacha20poly1305.NonceSizeX; i++ {
		if i%2 == 0 {
			data = append(data, keyHashed[i])
		}
	}

	return data
}
