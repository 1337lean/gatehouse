package main

import (
	"os"
	"runtime/debug"

	"github.com/1337lean/gatehouse/internal/app"
)

var version = "dev"

func main() {
	build, _ := debug.ReadBuildInfo()
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, resolvedVersion(version, build)))
}

func resolvedVersion(injected string, build *debug.BuildInfo) string {
	if injected != "dev" || build == nil || build.Main.Version == "" || build.Main.Version == "(devel)" {
		return injected
	}
	return build.Main.Version
}
