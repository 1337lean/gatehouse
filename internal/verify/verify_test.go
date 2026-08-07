package verify

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/1337lean/gatehouse/internal/policy"
	"github.com/1337lean/gatehouse/internal/report"
)

func TestBundleValidAndMismatch(t *testing.T) {
	d := t.TempDir()
	data := []byte("hello\n")
	os.WriteFile(filepath.Join(d, "README.md"), data, 0600)
	sum := sha256.Sum256(data)
	os.WriteFile(filepath.Join(d, "SHA256SUMS"), []byte(fmt.Sprintf("%x  README.md\n", sum)), 0600)
	p := policy.Default
	r, e := Bundle(d, p)
	if e != nil || !r.Valid {
		t.Fatalf("%+v %v", r, e)
	}
	os.WriteFile(filepath.Join(d, "README.md"), []byte("bad"), 0600)
	r, _ = Bundle(d, p)
	if r.Valid {
		t.Fatal("expected violation")
	}
}
func TestSBOMAndProvenance(t *testing.T) {
	d := t.TempDir()
	artifact := []byte("x")
	os.WriteFile(filepath.Join(d, "a.txt"), artifact, 0600)
	sum := sha256.Sum256(artifact)
	os.WriteFile(filepath.Join(d, "sbom.json"), []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0600)
	os.WriteFile(filepath.Join(d, "prov.json"), []byte(fmt.Sprintf(`{"subject":[{"name":"a.txt","digest":{"sha256":"%x"}}],"predicate":{"repository":"r","ref":"main","workflow":"w"}}`, sum)), 0600)
	p := policy.Policy{Version: 1, SBOM: policy.SBOM{Required: true, Globs: []string{"sbom.json"}, Formats: []string{"cyclonedx"}}, Provenance: policy.Provenance{Required: true, Globs: []string{"prov.json"}, Repository: "r", Ref: "main", Workflow: "w"}}
	r, e := Bundle(d, p)
	if e != nil || !r.Valid {
		t.Fatalf("%+v %v", r, e)
	}
}

func TestConfiguredMetadataConstraintsRequireAMatch(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name   string
		policy policy.Policy
		rule   string
	}{
		{
			name: "SBOM format",
			policy: policy.Policy{
				Version: 1,
				SBOM:    policy.SBOM{Globs: []string{"missing.json"}, Formats: []string{"cyclonedx"}},
			},
			rule: "sbom-required",
		},
		{
			name: "provenance constraint",
			policy: policy.Policy{
				Version:    1,
				Provenance: policy.Provenance{Globs: []string{"missing.json"}, Repository: "example/project"},
			},
			rule: "provenance-required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Bundle(directory, test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRule(result.Findings, test.rule) {
				t.Fatalf("unexpected findings %#v", result.Findings)
			}
		})
	}
}
func TestAdversarialProvenance(t *testing.T) {
	artifact := []byte("x")
	sum := sha256.Sum256(artifact)
	tests := []struct {
		name string
		json string
		rule string
	}{
		{"constraint-wrong-location", fmt.Sprintf(`{"subject":[{"name":"..artifact","digest":{"sha256":"%x"}}],"repository":"r","predicate":{"repository":"evil","ref":"main","workflow":"w"}}`, sum), "provenance-constraint"},
		{"duplicate-constraint", fmt.Sprintf(`{"subject":[{"name":"..artifact","digest":{"sha256":"%x"}}],"predicate":{"repository":"r","repository":"evil","ref":"main","workflow":"w"}}`, sum), "provenance-json"},
		{"wrong-type", fmt.Sprintf(`{"subject":[{"name":"..artifact","digest":{"sha256":"%x"}}],"predicate":{"repository":["r"],"ref":"main","workflow":"w"}}`, sum), "provenance-json"},
		{"case-alias", fmt.Sprintf(`{"Subject":[{"name":"..artifact","digest":{"sha256":"%x"}}],"Predicate":{"repository":"r","ref":"main","workflow":"w"}}`, sum), "provenance-json"},
		{"duplicate-subject", fmt.Sprintf(`{"subject":[{"name":"..artifact","digest":{"sha256":"%x"}},{"name":"dir/../..artifact","digest":{"sha256":"%x"}}],"predicate":{"repository":"r","ref":"main","workflow":"w"}}`, sum, sum), "provenance-subject"},
		{"traversal", fmt.Sprintf(`{"subject":[{"name":"../artifact","digest":{"sha256":"%x"}}],"predicate":{"repository":"r","ref":"main","workflow":"w"}}`, sum), "provenance-subject"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, "..artifact"), artifact, 0600)
			os.WriteFile(filepath.Join(d, "prov.json"), []byte(tc.json), 0600)
			p := policy.Policy{Version: 1, Provenance: policy.Provenance{Globs: []string{"prov.json"}, Repository: "r", Ref: "main", Workflow: "w", RequiredSubjects: []string{"..artifact"}}}
			r, err := Bundle(d, p)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRule(r.Findings, tc.rule) {
				t.Fatalf("findings %#v lack %q", r.Findings, tc.rule)
			}
		})
	}
}

func TestChecksumNormalizedDuplicateAndSafeDotDotName(t *testing.T) {
	d := t.TempDir()
	data := []byte("x")
	os.WriteFile(filepath.Join(d, "..artifact"), data, 0600)
	sum := sha256.Sum256(data)
	manifest := fmt.Sprintf("%x  ..artifact\n%x  dir/../..artifact\n", sum, sum)
	os.WriteFile(filepath.Join(d, "SUMS"), []byte(manifest), 0600)
	r, err := Bundle(d, policy.Policy{Version: 1, Checksums: "SUMS"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(r.Findings, "checksums") || !strings.Contains(fmt.Sprint(r.Findings), "duplicate normalized") {
		t.Fatalf("unexpected findings %#v", r.Findings)
	}
}

func TestChecksumManifestSupportsSpacesAndLeadingAsterisks(t *testing.T) {
	directory := t.TempDir()
	files := map[string][]byte{
		"artifact file": []byte("with spaces"),
		"*artifact":     []byte("leading asterisk"),
	}
	var manifest strings.Builder
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&manifest, "%x  %s\r\n", sum, name)
	}
	if err := os.WriteFile(filepath.Join(directory, "SUMS"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(directory, policy.Policy{Version: 1, Checksums: "SUMS"})
	if err != nil || !result.Valid {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

func TestRejectSymlinkedBundleFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "artifact")); err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(directory, policy.Policy{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(result.Findings, "symlink") {
		t.Fatalf("unexpected findings %#v", result.Findings)
	}
}

func TestMetadataReadsAreBounded(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		policy   policy.Policy
		rule     string
		limit    int64
	}{
		{
			name:     "checksum manifest",
			filename: "SHA256SUMS",
			policy:   policy.Policy{Version: 1, Checksums: "SHA256SUMS"},
			rule:     "checksums-size",
			limit:    maxChecksumManifestBytes,
		},
		{
			name:     "SBOM",
			filename: "sbom.json",
			policy: policy.Policy{
				Version: 1,
				SBOM:    policy.SBOM{Required: true, Globs: []string{"sbom.json"}},
			},
			rule:  "sbom-size",
			limit: maxMetadataBytes,
		},
		{
			name:     "provenance",
			filename: "provenance.json",
			policy: policy.Policy{
				Version:    1,
				Provenance: policy.Provenance{Required: true, Globs: []string{"provenance.json"}},
			},
			rule:  "provenance-size",
			limit: maxMetadataBytes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			file, err := os.Create(filepath.Join(directory, test.filename))
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(test.limit + 1); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			result, err := Bundle(directory, test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRule(result.Findings, test.rule) {
				t.Fatalf("unexpected findings %#v", result.Findings)
			}
		})
	}
}

func TestOversizedArtifactsAreNotHashed(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "artifact.bin")
	file, err := os.Create(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(64 << 20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := strings.Repeat("0", sha256.Size*2) + "  artifact.bin\n"
	if err := os.WriteFile(filepath.Join(directory, "SUMS"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(directory, policy.Policy{Version: 1, Checksums: "SUMS", MaxFileSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(result.Findings, "max-file-size") || !strings.Contains(fmt.Sprint(result.Findings), "was not hashed") {
		t.Fatalf("unexpected findings %#v", result.Findings)
	}
}

func TestBoundedWalkerCountsAllEntryTypes(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"one", "two", "three"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := walkBounded(root, 2, func(string, os.DirEntry) error { return nil }); err != errTooManyEntries {
		t.Fatalf("walker error = %v", err)
	}
}

func hasRule(findings []report.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}

func FuzzChecksumManifest(f *testing.F) {
	f.Add("bad")
	f.Fuzz(func(t *testing.T, s string) {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "SUMS"), []byte(s), 0600)
		_, _ = Bundle(d, policy.Policy{Version: 1, Checksums: "SUMS"})
	})
}
