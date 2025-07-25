package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/pkg/password"
)

var (
	pwgenLength   int
	pwgenSpecial  int
	pwgenNumbers  int
	pwgenVariants int
	pwgenString   bool
)

var pwgenCmd = &cobra.Command{
	Use:   "pwgen",
	Short: "Generate a random password",
	RunE: func(_ *cobra.Command, _ []string) error {
		for i := 0; i < pwgenVariants; i++ {
			var (
				length  = pwgenLength
				special = pwgenSpecial
				numbers = pwgenNumbers
			)

			if pwgenString {
				special = 0
				numbers = 0
			}

			pass := password.Generate(length, special, numbers)
			fmt.Println(pass)
		}
		return nil
	},
}

func init() {
	pwgenCmd.Flags().IntVarP(&pwgenLength, "length", "l", password.DefaultPasswordLength, "Password length")
	pwgenCmd.Flags().IntVar(&pwgenSpecial, "special", password.DefaultSpecialCharsLength, "Number of special characters")
	pwgenCmd.Flags().IntVar(&pwgenNumbers, "numbers", password.DefaultNumbersLength, "Number of numbers")
	pwgenCmd.Flags().IntVarP(&pwgenVariants, "variants", "v", 5, "Number of variants")
	pwgenCmd.Flags().BoolVarP(&pwgenString, "string", "s", false, "String only characters")
}
