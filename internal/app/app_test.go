package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var errTestWrite = errors.New("test writer failed")

type failingWriter struct {
	partial bool
}

func (w failingWriter) Write(data []byte) (int, error) {
	if w.partial && len(data) > 0 {
		return 1, nil
	}
	return 0, errTestWrite
}

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

func TestCLIExitCodeContract(t *testing.T) {
	directory := t.TempDir()
	validPolicy := filepath.Join(directory, "valid.json")
	invalidPolicy := filepath.Join(directory, "invalid.json")
	denyingPolicy := filepath.Join(directory, "denying.json")
	for path, contents := range map[string]string{
		validPolicy:   `{"version":1}`,
		invalidPolicy: `{`,
		denyingPolicy: `{"version":1,"requiredGlobs":["missing"]}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"invalid flag", []string{"verify", "--unknown"}, ExitUsage},
		{"invalid policy", []string{"policy", "check", "--policy", invalidPolicy}, ExitUsage},
		{"policy denial", []string{"verify", "--policy", denyingPolicy, directory}, ExitViolation},
		{"success", []string{"verify", "--policy", validPolicy, directory}, ExitOK},
		{"operational failure", []string{"verify", "--policy", filepath.Join(directory, "missing"), directory}, ExitInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := Run(test.args, &stdout, &stderr, "test"); got != test.want {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", got, test.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestAllOutputFailuresAreOperational(t *testing.T) {
	directory := t.TempDir()
	validPolicy := filepath.Join(directory, "valid.json")
	invalidPolicy := filepath.Join(directory, "invalid.json")
	denyingPolicy := filepath.Join(directory, "denying.json")
	for path, contents := range map[string]string{
		validPolicy:   `{"version":1}`,
		invalidPolicy: `{`,
		denyingPolicy: `{"version":1,"requiredGlobs":["missing"]}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name      string
		args      []string
		failOut   bool
		failError bool
		partial   bool
	}{
		{"version", []string{"version"}, true, false, false},
		{"help partial write", []string{"help"}, true, false, true},
		{"missing command", nil, false, true, false},
		{"unknown command partial write", []string{"unknown"}, false, true, true},
		{"flag diagnostics", []string{"verify", "--unknown"}, false, true, false},
		{"policy human success", []string{"policy", "check", "--policy", validPolicy}, true, false, false},
		{"policy human error", []string{"policy", "check", "--policy", invalidPolicy}, false, true, true},
		{"policy json", []string{"policy", "check", "--format", "json", "--policy", validPolicy}, true, false, true},
		{"verify human success", []string{"verify", "--policy", validPolicy, directory}, true, false, false},
		{"verify human denial", []string{"verify", "--policy", denyingPolicy, directory}, true, false, true},
		{"verify json", []string{"verify", "--format", "json", "--policy", validPolicy, directory}, true, false, false},
		{"verify sarif", []string{"verify", "--format", "sarif", "--policy", validPolicy, directory}, true, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr io.Writer = io.Discard, io.Discard
			if test.failOut {
				stdout = failingWriter{partial: test.partial}
			}
			if test.failError {
				stderr = failingWriter{partial: test.partial}
			}
			if got := Run(test.args, stdout, stderr, "test"); got != ExitInternal {
				t.Fatalf("exit = %d, want %d", got, ExitInternal)
			}
		})
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
