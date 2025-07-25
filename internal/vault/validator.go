package vault

import (
	"fmt"
	"regexp"
)

var (
	validateNameRegex    = regexp.MustCompile("^([0-9a-zA-Z-_.]{3,32})$")
	validateKeyNameRegex = regexp.MustCompile("^([0-9a-zA-Z-_./]{3,128})$")
)

func ValidateName(name string) error {
	if !validateNameRegex.MatchString(name) {
		return fmt.Errorf("invalid vault name: %s", name)
	}

	return nil
}

func ValidateKeyName(name string) error {
	if !validateKeyNameRegex.MatchString(name) {
		return fmt.Errorf("invalid key name: %s", name)
	}

	return nil
}
