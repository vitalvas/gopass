package version

import (
	"runtime/debug"
	"testing"
)

func TestVersion(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()

	got := Version()
	if ok {
		if got != bi.Main.Version {
			t.Errorf("Version() = %q, want %q", got, bi.Main.Version)
		}
	} else {
		if got != BuildVersion {
			t.Errorf("Version() = %q, want %q", got, BuildVersion)
		}
	}
}
