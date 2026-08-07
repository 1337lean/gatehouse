package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/1337lean/gatehouse/internal/bundlepath"
	"github.com/1337lean/gatehouse/internal/strictjson"
)

const (
	CurrentVersion = 1
	MaxPolicySize  = 1 << 20
)

type Policy struct {
	Version           int        `json:"version"`
	Checksums         string     `json:"checksums,omitempty"`
	AllowedExtensions []string   `json:"allowedExtensions,omitempty"`
	DeniedExtensions  []string   `json:"deniedExtensions,omitempty"`
	MaxFileSize       int64      `json:"maxFileSize,omitempty"`
	RequiredGlobs     []string   `json:"requiredGlobs,omitempty"`
	SBOM              SBOM       `json:"sbom,omitempty"`
	Provenance        Provenance `json:"provenance,omitempty"`
}
type SBOM struct {
	Required bool     `json:"required,omitempty"`
	Globs    []string `json:"globs,omitempty"`
	Formats  []string `json:"formats,omitempty"`
}
type Provenance struct {
	Required         bool     `json:"required,omitempty"`
	Globs            []string `json:"globs,omitempty"`
	Repository       string   `json:"repository,omitempty"`
	Ref              string   `json:"ref,omitempty"`
	Workflow         string   `json:"workflow,omitempty"`
	RequiredSubjects []string `json:"requiredSubjects,omitempty"`
}

var Default = Policy{Version: 1, Checksums: "SHA256SUMS", DeniedExtensions: []string{".exe", ".dll"}, MaxFileSize: 100 * 1024 * 1024, RequiredGlobs: []string{"README*"}}

// ErrInvalid identifies policy content or semantics that the user must fix. I/O
// and filesystem errors are deliberately left outside this class so callers can
// distinguish configuration mistakes from operational failures.
var ErrInvalid = errors.New("invalid policy")

func Load(path string) (Policy, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Policy{}, err
	}
	if !info.Mode().IsRegular() {
		return Policy{}, errors.New("policy is not a regular file")
	}
	if info.Size() > MaxPolicySize {
		return Policy{}, fmt.Errorf("policy exceeds %d bytes", MaxPolicySize)
	}
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return Policy{}, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Policy{}, errors.New("policy changed while opening")
	}
	if openedInfo.Size() > MaxPolicySize {
		return Policy{}, fmt.Errorf("policy exceeds %d bytes", MaxPolicySize)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPolicySize+1))
	if err != nil {
		return Policy{}, err
	}
	if len(b) > MaxPolicySize {
		return Policy{}, fmt.Errorf("policy exceeds %d bytes", MaxPolicySize)
	}
	if err := strictjson.Validate(b); err != nil {
		return Policy{}, fmt.Errorf("%w: decode policy: %v", ErrInvalid, err)
	}
	if err := validatePolicyKeys(b); err != nil {
		return Policy{}, fmt.Errorf("%w: decode policy: %v", ErrInvalid, err)
	}
	var p Policy
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("%w: decode policy: %v", ErrInvalid, err)
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return p, fmt.Errorf("%w: decode policy: trailing data", ErrInvalid)
	}
	if err := Validate(p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return p, nil
}

func validatePolicyKeys(data []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	topLevel := map[string]struct{}{
		"version":           {},
		"checksums":         {},
		"allowedExtensions": {},
		"deniedExtensions":  {},
		"maxFileSize":       {},
		"requiredGlobs":     {},
		"sbom":              {},
		"provenance":        {},
	}
	if err := rejectUnknownKeys(document, topLevel); err != nil {
		return err
	}
	if raw, ok := document["sbom"]; ok {
		if err := validateNestedKeys(raw, map[string]struct{}{
			"required": {},
			"globs":    {},
			"formats":  {},
		}); err != nil {
			return fmt.Errorf("sbom: %w", err)
		}
	}
	if raw, ok := document["provenance"]; ok {
		if err := validateNestedKeys(raw, map[string]struct{}{
			"required":         {},
			"globs":            {},
			"repository":       {},
			"ref":              {},
			"workflow":         {},
			"requiredSubjects": {},
		}); err != nil {
			return fmt.Errorf("provenance: %w", err)
		}
	}
	return nil
}

func validateNestedKeys(data json.RawMessage, allowed map[string]struct{}) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	return rejectUnknownKeys(object, allowed)
}

func rejectUnknownKeys(document map[string]json.RawMessage, allowed map[string]struct{}) error {
	for key := range document {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

func Validate(p Policy) error {
	if p.Version != CurrentVersion {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.MaxFileSize < 0 {
		return errors.New("maxFileSize must not be negative")
	}
	seen := map[string]bool{}
	for _, e := range append(append([]string{}, p.AllowedExtensions...), p.DeniedExtensions...) {
		if e == "" || !strings.HasPrefix(e, ".") || e != strings.ToLower(e) || strings.ContainsAny(e, `/\*?[]`) {
			return fmt.Errorf("invalid extension %q", e)
		}
		if seen[e] {
			return fmt.Errorf("duplicate or conflicting extension %q", e)
		}
		seen[e] = true
	}
	if err := validateGlobs("requiredGlobs", p.RequiredGlobs); err != nil {
		return err
	}
	if err := validateGlobs("sbom.globs", p.SBOM.Globs); err != nil {
		return err
	}
	if err := validateGlobs("provenance.globs", p.Provenance.Globs); err != nil {
		return err
	}
	for _, f := range p.SBOM.Formats {
		if f != "cyclonedx" && f != "spdx" {
			return fmt.Errorf("unsupported SBOM format %q", f)
		}
	}
	if p.Checksums != "" {
		if _, err := bundlepath.Normalize(p.Checksums); err != nil {
			return fmt.Errorf("invalid checksums path %q: %w", p.Checksums, err)
		}
	}
	if (p.SBOM.Required || len(p.SBOM.Formats) > 0) && len(p.SBOM.Globs) == 0 {
		return errors.New("sbom.globs is required when SBOM checks are configured")
	}
	provenanceConfigured := p.Provenance.Required ||
		p.Provenance.Repository != "" ||
		p.Provenance.Ref != "" ||
		p.Provenance.Workflow != "" ||
		len(p.Provenance.RequiredSubjects) > 0
	if provenanceConfigured && len(p.Provenance.Globs) == 0 {
		return errors.New("provenance.globs is required when provenance checks are configured")
	}
	subjects := map[string]struct{}{}
	for _, name := range p.Provenance.RequiredSubjects {
		clean, err := bundlepath.Normalize(name)
		if err != nil {
			return fmt.Errorf("invalid required provenance subject %q: %w", name, err)
		}
		if _, ok := subjects[clean]; ok {
			return fmt.Errorf("duplicate required provenance subject %q", clean)
		}
		subjects[clean] = struct{}{}
	}
	return nil
}

func validateGlobs(field string, globs []string) error {
	seen := make(map[string]struct{}, len(globs))
	for _, glob := range globs {
		if glob == "" || strings.ContainsRune(glob, '\x00') {
			return fmt.Errorf("%s contains an invalid glob %q", field, glob)
		}
		if _, err := path.Match(glob, "x"); err != nil {
			return fmt.Errorf("invalid glob %q in %s: %w", glob, field, err)
		}
		if _, ok := seen[glob]; ok {
			return fmt.Errorf("duplicate glob %q in %s", glob, field)
		}
		seen[glob] = struct{}{}
	}
	return nil
}
