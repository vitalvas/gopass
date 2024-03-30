package vault

import (
	"fmt"
	"regexp"
)

func ValidateName(name string) error {
	if match, err := regexp.MatchString("^([0-9a-z-_.]{3,32})$", name); err != nil {
		return fmt.Errorf("failed to validate vault name: %w", err)
	} else if !match {
		return fmt.Errorf("invalid vault name: %s", name)
	}

	return nil
}