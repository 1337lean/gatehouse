package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "p.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"maxFileSize":10}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got.MaxFileSize != 10 {
		t.Fatalf("got %+v, %v", got, err)
	}
}
func TestRejectUnknownAndVersion(t *testing.T) {
	for _, s := range []string{
		`{"version":1,"wat":1}`,
		`{"version":2}`,
		`{"Version":1}`,
		`{"version":1,"provenance":{"Required":true}}`,
	} {
		d := t.TempDir()
		p := filepath.Join(d, "p")
		os.WriteFile(p, []byte(s), 0600)
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted %s", s)
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error %q is not classified as invalid policy", err)
		}
	}
}
func TestRejectDuplicateKeysAndOversizedPolicy(t *testing.T) {
	d := t.TempDir()
	for name, data := range map[string][]byte{
		"duplicate": []byte(`{"version":1,"version":1}`),
		"nested":    []byte(`{"version":1,"provenance":{"required":true,"required":false}}`),
		"oversized": []byte(`{"version":1,"padding":"` + strings.Repeat("x", MaxPolicySize) + `"}`),
	} {
		path := filepath.Join(d, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("accepted %s policy", name)
		}
	}
}

func TestPolicySizeBoundary(t *testing.T) {
	directory := t.TempDir()
	base := []byte(`{"version":1}`)
	for _, test := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exact limit", size: MaxPolicySize},
		{name: "limit plus one", size: MaxPolicySize + 1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents := append(append([]byte{}, base...), []byte(strings.Repeat(" ", test.size-len(base)))...)
			name := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.WriteFile(name, contents, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(name)
			if test.wantErr && (err == nil || !strings.Contains(err.Error(), "exceeds")) {
				t.Fatalf("error = %v, want size-limit error", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("exact-limit policy failed: %v", err)
			}
		})
	}
}

func TestValidateRequiredSubjects(t *testing.T) {
	if err := Validate(Policy{Version: 1, Provenance: Provenance{Globs: []string{"provenance.json"}, RequiredSubjects: []string{"..artifact"}}}); err != nil {
		t.Fatal(err)
	}
	for _, subjects := range [][]string{{"../artifact"}, {"artifact", "dir/../artifact"}} {
		if err := Validate(Policy{Version: 1, Provenance: Provenance{Globs: []string{"provenance.json"}, RequiredSubjects: subjects}}); err == nil {
			t.Errorf("accepted subjects %#v", subjects)
		}
	}
}

func TestValidateRejectsChecksWithoutSelectors(t *testing.T) {
	tests := []Policy{
		{Version: 1, SBOM: SBOM{Required: true}},
		{Version: 1, SBOM: SBOM{Formats: []string{"cyclonedx"}}},
		{Version: 1, Provenance: Provenance{Repository: "example/project"}},
		{Version: 1, Provenance: Provenance{RequiredSubjects: []string{"artifact"}}},
	}
	for _, p := range tests {
		if err := Validate(p); err == nil {
			t.Errorf("accepted ineffective policy %+v", p)
		}
	}
}

func TestValidateRejectsDuplicateAndNonPortableGlobs(t *testing.T) {
	for _, globs := range [][]string{{"*.json", "*.json"}, {""}, {"["}} {
		p := Policy{Version: 1, RequiredGlobs: globs}
		if err := Validate(p); err == nil {
			t.Errorf("accepted globs %#v", globs)
		}
	}
}

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"requiredGlobs":["深い/✓.json"]}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`{"version":1,"requiredGlobs":["*.json","*.json"]}`))
	f.Add([]byte(`{"version":1,"unknown":{"a":{"b":{"c":{"d":{"e":true}}}}}}`))
	f.Add([]byte(`{"version":1,"provenance":{"globs":["*.json"],"requiredSubjects":["a","a"]}}`))
	f.Add([]byte(`{"version":1,"maxFileSize":9223372036854775807}`))
	f.Add([]byte(`{"version":1,"maxFileSize":-1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := t.TempDir()
		p := filepath.Join(d, "p")
		if os.WriteFile(p, b, 0600) != nil {
			return
		}
		_, _ = Load(p)
	})
}
