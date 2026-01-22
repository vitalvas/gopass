package vault

type Vault interface {
	ListKeys() ([][]byte, error)
	GetKey(keyID []byte) (encryptedKey []byte, encryptedValue []byte, err error)
	SetKey(keyID []byte, encryptedKey []byte, encryptedValue []byte) error
	DeleteKey(keyID []byte) error

	SetTestKey(value []byte) error
	GetTestKey() ([]byte, error)

	Close() error
}
