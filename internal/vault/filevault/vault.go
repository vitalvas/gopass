package filevault

import (
	"github.com/vitalvas/gopass/internal/vault"
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
