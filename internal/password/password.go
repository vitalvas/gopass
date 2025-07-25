package password

import (
	"math/rand"
	"slices"
	"strings"
)

const (
	lowerCharSet   = "abcdefghkmnpqrstuvwxyz"
	upperCharSet   = "ABCDEFGHJKMNPQRSTUVWXYZ"
	numberSet      = "23456789"
	specialCharSet = "_!@#$%^&*"

	allCharSet = lowerCharSet + upperCharSet

	DefaultLength = -1

	DefaultPasswordLength     = 15
	DefaultSpecialCharsLength = 3
	DefaultNumbersLength      = 3
)

func Generate(passwordLength, specialCharsLength, numbersLength int) string {
	var password strings.Builder

	if passwordLength <= DefaultLength {
		passwordLength = DefaultPasswordLength
	}

	if specialCharsLength <= DefaultLength {
		specialCharsLength = DefaultSpecialCharsLength
	}

	if numbersLength <= DefaultLength {
		numbersLength = DefaultNumbersLength
	}

	// Set special character
	for i := 0; i < specialCharsLength; i++ {
		random := rand.Intn(len(specialCharSet)) //nolint:gosec
		password.WriteString(string(specialCharSet[random]))
	}

	// Set numeric
	for i := 0; i < numbersLength; i++ {
		random := rand.Intn(len(numberSet)) //nolint:gosec
		password.WriteString(string(numberSet[random]))
	}

	remainingLength := passwordLength - specialCharsLength - numbersLength
	for i := 0; i < remainingLength; i++ {
		random := rand.Intn(len(allCharSet)) //nolint:gosec
		password.WriteString(string(allCharSet[random]))
	}

	charsList := strings.Split(allCharSet, "")

	inRune := []rune(password.String())
	for z := 0; z < 10_000; z++ {
		if z > 100 &&
			slices.Contains(charsList, string(inRune[0])) &&
			slices.Contains(charsList, string(inRune[len(inRune)-1])) {
			break
		}

		rand.Shuffle(len(inRune), func(i, j int) {
			inRune[i], inRune[j] = inRune[j], inRune[i]
		})
	}

	return string(inRune)
}
