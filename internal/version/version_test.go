package version

import (
	"runtime/debug"
	"testing"
)

func TestVersion(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("ReadBuildInfo failed")
	}

	if got, want := Version(), bi.Main.Version; got != want {
		t.Errorf("Version() = %q; want %q", got, want)
	}
}
