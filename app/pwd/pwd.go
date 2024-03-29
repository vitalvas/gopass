package pwd

import (
	"math/rand"
	"strings"
)

const (
	lowerCharSet   = "abcdefghkmnpqrstuvwxyz"
	upperCharSet   = "ABCDEFGHJKMNPQRSTUVWXYZ"
	numberSet      = "23456789"
	specialCharSet = "_!@#%+$"
	allCharSet     = lowerCharSet + upperCharSet
)

func GeneratePassword(passwordLength, specialCharsLen, numLen int) string {
	var password strings.Builder

	// Set special character
	for i := 0; i < specialCharsLen; i++ {
		random := rand.Intn(len(specialCharSet)) //nolint:gosec
		password.WriteString(string(specialCharSet[random]))
	}

	// Set numeric
	for i := 0; i < numLen; i++ {
		random := rand.Intn(len(numberSet)) //nolint:gosec
		password.WriteString(string(numberSet[random]))
	}

	remainingLength := passwordLength - specialCharsLen - numLen
	for i := 0; i < remainingLength; i++ {
		random := rand.Intn(len(allCharSet)) //nolint:gosec
		password.WriteString(string(allCharSet[random]))
	}

	inRune := []rune(password.String())
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})

	return string(inRune)
}
