package version

import "runtime/debug"

var BuildVersion = "v0.1.0"

func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		return bi.Main.Version
	}

	return BuildVersion
}
