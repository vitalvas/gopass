package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vitalvas/gopass/app/pwd"
)

var pwgenCmd = &cobra.Command{
	Use: "pwgen",
	Run: pwgen,
}

var pwgenLen int
var pwgenIPMI bool
var pwgenStr bool

func init() {
	rootCmd.AddCommand(pwgenCmd)

	pwgenCmd.PersistentFlags().IntVar(&pwgenLen, "len", 24, "Password length")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenIPMI, "ipmi", false, "Password for IPMI")
	pwgenCmd.PersistentFlags().BoolVarP(&pwgenStr, "str", "s", false, "String chars only")
}

func pwgen(cmd *cobra.Command, args []string) {
	specialCharsLen := 2
	numLen := 3

	if pwgenStr {
		specialCharsLen = 0
		numLen = 0
	}

	if pwgenIPMI {
		// Can be 16 or 20 bytes in ASCII length. In real - 15 or 19 chars
		specialCharsLen = 0
		numLen = 0
		pwgenLen = 15
	}

	pass := pwd.GeneratePassword(pwgenLen, specialCharsLen, numLen)

	fmt.Println(pass)
}
