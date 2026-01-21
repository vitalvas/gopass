package encryptor

import (
	"golang.org/x/crypto/blake2b"
)

const nonceSize = 12

func getNonce(key string) []byte {
	keyHashed := blake2b.Sum256([]byte(key))

	return keyHashed[:nonceSize]
}
