package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCLIIntegration(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "p.json")
	var out, err bytes.Buffer
	if c := Run([]string{"init", "--policy", p}, &out, &err, "test"); c != 0 {
		t.Fatal(c, err.String())
	}
	out.Reset()
	if c := Run([]string{"policy", "check", "--policy", p}, &out, &err, "test"); c != 0 {
		t.Fatal(c, err.String())
	}
	os.WriteFile(filepath.Join(d, "README.md"), []byte("x"), 0600)
	if c := Run([]string{"verify", "--policy", p, d}, &out, &err, "test"); c != 1 {
		t.Fatalf("exit %d", c)
	}
}
func TestSARIFAndExitCodes(t *testing.T) {
	d := t.TempDir()
	policyPath := filepath.Join(d, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version":1,"requiredGlobs":["missing"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"verify", "--policy", policyPath, "--format", "sarif", d}, &out, &errOut, "test"); code != ExitViolation {
		t.Fatalf("violation exit = %d, stderr %q", code, errOut.String())
	}
	var sarif map[string]any
	if err := json.Unmarshal(out.Bytes(), &sarif); err != nil || sarif["version"] != "2.1.0" {
		t.Fatalf("invalid SARIF: %v %#v", err, sarif)
	}
	if code := Run([]string{"verify", "--policy", policyPath, "--format", "bogus", d}, &out, &errOut, "test"); code != ExitUsage {
		t.Fatalf("usage exit = %d", code)
	}
	if code := Run([]string{"verify", "--policy", filepath.Join(d, "missing"), d}, &out, &errOut, "test"); code != ExitInternal {
		t.Fatalf("internal exit = %d", code)
	}
}

func TestVersion(t *testing.T) {
	var o, e bytes.Buffer
	if c := Run([]string{"version"}, &o, &e, "1.2.3"); c != 0 || o.String() != "1.2.3\n" {
		t.Fatalf("%d %q", c, o.String())
	}
}

func TestInitDoesNotFollowPolicySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink replacement semantics differ on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	policyPath := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(target, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, policyPath); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"init", "--force", "--policy", policyPath}, &stdout, &stderr, "test"); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	unchanged, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != "do not overwrite" {
		t.Fatalf("symlink target was overwritten: %q", unchanged)
	}
	info, err := os.Lstat(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("policy mode = %v", info.Mode())
	}
}
