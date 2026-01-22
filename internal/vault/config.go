package vault

import "github.com/vitalvas/gopass/internal/encryptor"

type Config struct {
	Name    string          `json:"name"`
	Address string          `json:"address"`
	Keys    *encryptor.Keys `json:"keys"`
}
