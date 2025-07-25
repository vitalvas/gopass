package vault

type Vault interface {
	ListKeys() ([][]byte, error)
	GetKey(key []byte) ([]byte, error)
	SetKey(key []byte, value []byte) error
	DeleteKey(key []byte) error

	SetTestKey(value []byte) error
	GetTestKey() ([]byte, error)

	Close() error
}
