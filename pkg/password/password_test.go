package password

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	password := Generate(DefaultLength, DefaultLength, DefaultLength)
	if len(password) != DefaultPasswordLength {
		t.Errorf("Password length is not equal to %d", DefaultPasswordLength)
	}
}
