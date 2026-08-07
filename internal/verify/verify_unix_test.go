//go:build !windows

package verify

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/1337lean/gatehouse/internal/policy"
)

func TestRejectFIFO(t *testing.T) {
	directory := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(directory, "pipe"), 0600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	result, err := Bundle(directory, policy.Policy{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(result.Findings, "regular-file") {
		t.Fatalf("unexpected findings %#v", result.Findings)
	}
}
