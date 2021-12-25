package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gopass",
	Short: "Simple password manager",
}

func Execute(version, commit, date string) error {
	rootCmd.Version = fmt.Sprintf("%s+%s (%s)", version, commit, date)

	return rootCmd.Execute()
}
