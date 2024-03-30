package filevault

import (
	"github.com/vitalvas/gopass/pkg/vault"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ vault.Vault = (*Vault)(nil)

type Vault struct {
	storagePath string
}

func New(storagePath string) *Vault {
	return &Vault{
		storagePath: storagePath,
	}
}

func (v *Vault) Close() error {
	return nil
}

func (v *Vault) ListKeys() ([][]byte, error) {
	return nil, nil
}

func (v *Vault) GetKey(_ []byte) ([]byte, error) {
	return nil, nil
}

func (v *Vault) SetKey(_ []byte, _ []byte) error {
	return nil
}

func (v *Vault) DeleteKey(_ []byte) error {
	return nil
}
