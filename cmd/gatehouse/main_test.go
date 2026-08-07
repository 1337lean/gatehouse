package main

import (
	"runtime/debug"
	"testing"
)

func TestResolvedVersion(t *testing.T) {
	tests := []struct {
		name     string
		injected string
		build    *debug.BuildInfo
		want     string
	}{
		{name: "release injection wins", injected: "1.2.3", build: &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, want: "1.2.3"},
		{name: "module version", injected: "dev", build: &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, want: "v0.1.0"},
		{name: "pseudo version", injected: "dev", build: &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20260807030432-1f0cc9725859"}}, want: "v0.0.0-20260807030432-1f0cc9725859"},
		{name: "local build", injected: "dev", build: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, want: "dev"},
		{name: "missing build info", injected: "dev", want: "dev"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolvedVersion(test.injected, test.build); got != test.want {
				t.Fatalf("resolvedVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
