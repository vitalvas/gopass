package vault

type Config struct {
	Name            string `json:"name"`
	Address         string `json:"address"`
	EncryptionKey   string `json:"encryption_key"`
	EncryptionValue string `json:"encryption_value,omitempty"`
}
