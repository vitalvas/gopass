package version

import "runtime/debug"

func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		return bi.Main.Version
	}

	return "v0.1.0"
}
