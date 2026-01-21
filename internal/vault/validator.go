package vault

import (
	"fmt"
	"regexp"
)

var (
	validateNameRegex    = regexp.MustCompile("^([0-9a-zA-Z-_.]{3,32})$")
	validateKeyNameRegex = regexp.MustCompile("^/[0-9a-zA-Z-_.]+(/[0-9a-zA-Z-_.]+)*$")
)

func ValidateName(name string) error {
	if !validateNameRegex.MatchString(name) {
		return fmt.Errorf("invalid vault name: %s", name)
	}

	return nil
}

func ValidateKeyName(name string) error {
	if len(name) < 3 || len(name) > 128 {
		return fmt.Errorf("invalid key name length: %s", name)
	}

	if !validateKeyNameRegex.MatchString(name) {
		return fmt.Errorf("invalid key name: %s (must start with '/' and look like a filepath)", name)
	}

	return nil
}
