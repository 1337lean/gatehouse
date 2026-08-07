//go:build !windows

package verify

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/1337lean/gatehouse/internal/policy"
)

func TestChecksumManifestSupportsLeadingAsterisk(t *testing.T) {
	directory := t.TempDir()
	contents := []byte("leading asterisk")
	name := "*artifact"
	if err := os.WriteFile(filepath.Join(directory, name), contents, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	manifest := []byte(fmt.Sprintf("%x  %s\n", digest, name))
	if err := os.WriteFile(filepath.Join(directory, "SUMS"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Bundle(directory, policy.Policy{Version: 1, Checksums: "SUMS"})
	if err != nil || !result.Valid {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

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
