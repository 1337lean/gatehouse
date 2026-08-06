package verify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1337lean/gatehouse/internal/bundlepath"
	"github.com/1337lean/gatehouse/internal/policy"
	"github.com/1337lean/gatehouse/internal/report"
	"github.com/1337lean/gatehouse/internal/strictjson"
)

const (
	maxBundleEntries         = 100_000
	maxChecksumManifestBytes = 16 << 20
	maxMetadataBytes         = 16 << 20
)

var (
	errMetadataTooLarge = errors.New("metadata exceeds verification limit")
	errTooManyEntries   = errors.New("bundle contains too many entries")
)

func Bundle(rootPath string, p policy.Policy) (report.Result, error) {
	rootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return report.Result{}, err
	}
	info, err := os.Lstat(rootPath)
	if err != nil {
		return report.Result{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return report.Result{}, errors.New("bundle is not a regular directory")
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return report.Result{}, err
	}
	defer root.Close()
	openedInfo, err := root.Stat(".")
	if err != nil {
		return report.Result{}, err
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		return report.Result{}, errors.New("bundle directory changed while opening")
	}

	checksumPath := ""
	if p.Checksums != "" {
		checksumPath, err = bundlepath.Normalize(p.Checksums)
		if err != nil {
			return report.Result{}, fmt.Errorf("invalid checksum manifest path: %w", err)
		}
	}

	var findings []report.Finding
	files := make([]string, 0)
	oversized := make(map[string]bool)
	err = walkBounded(root, maxBundleEntries, func(name string, entry fs.DirEntry) error {
		if entry.Type()&os.ModeSymlink != 0 {
			findings = append(findings, fail("symlink", name, "symbolic links are not allowed"))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			findings = append(findings, fail("regular-file", name, "non-regular files are not allowed"))
			return nil
		}
		files = append(files, name)
		extension := strings.ToLower(path.Ext(name))
		if p.MaxFileSize > 0 && entryInfo.Size() > p.MaxFileSize {
			oversized[name] = true
			findings = append(findings, fail(
				"max-file-size",
				name,
				fmt.Sprintf("size %d exceeds %d", entryInfo.Size(), p.MaxFileSize),
			))
		}
		if contains(p.DeniedExtensions, extension) {
			findings = append(findings, fail("denied-extension", name, "extension is denied"))
		}
		if len(p.AllowedExtensions) > 0 && !contains(p.AllowedExtensions, extension) && name != checksumPath {
			findings = append(findings, fail("allowed-extension", name, "extension is not allowed"))
		}
		return nil
	})
	if errors.Is(err, errTooManyEntries) {
		findings = append(findings, fail(
			"bundle-entry-limit",
			"",
			fmt.Sprintf("bundle contains more than %d filesystem entries", maxBundleEntries),
		))
		return result(findings), nil
	}
	if err != nil {
		return report.Result{}, err
	}
	sort.Strings(files)
	digests := newDigestCache(root)

	for _, glob := range p.RequiredGlobs {
		if !matches(glob, files) {
			findings = append(findings, fail("required-glob", "", fmt.Sprintf("no file matches %q", glob)))
		}
	}
	if checksumPath != "" {
		findings = append(findings, checkSums(root, checksumPath, files, oversized, digests)...)
	}
	findings = append(findings, checkSBOM(root, files, oversized, p.SBOM)...)
	findings = append(findings, checkProvenance(root, files, oversized, digests, p.Provenance)...)

	return result(findings), nil
}

func result(findings []report.Finding) report.Result {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Message < findings[j].Message
	})
	return report.Result{Valid: len(findings) == 0, Findings: findings}
}

func walkBounded(root *os.Root, limit int, visit func(string, fs.DirEntry) error) error {
	pending := []string{"."}
	entries := 0
	for len(pending) > 0 {
		directoryName := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		directory, err := openDirectory(root, directoryName)
		if err != nil {
			return err
		}

		for {
			batch, readErr := directory.ReadDir(256)
			for _, entry := range batch {
				entries++
				if entries > limit {
					directory.Close()
					return errTooManyEntries
				}
				name := entry.Name()
				if directoryName != "." {
					name = path.Join(directoryName, name)
				}
				if err := visit(name, entry); err != nil {
					directory.Close()
					return err
				}
				if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
					pending = append(pending, name)
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				directory.Close()
				return readErr
			}
		}
		if err := directory.Close(); err != nil {
			return err
		}
	}
	return nil
}

func openDirectory(root *os.Root, relative string) (*os.File, error) {
	name := filepath.FromSlash(relative)
	before, err := root.Lstat(name)
	if err != nil || !before.IsDir() {
		return nil, errors.New("not a directory")
	}
	directory, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := directory.Stat()
	if err != nil {
		directory.Close()
		return nil, err
	}
	if !after.IsDir() || !os.SameFile(before, after) {
		directory.Close()
		return nil, errors.New("directory changed while opening")
	}
	return directory, nil
}

func fail(rule, filePath, message string) report.Finding {
	if filePath != "" {
		filePath = path.Clean(filepath.ToSlash(filePath))
	}
	return report.Finding{Rule: rule, Path: filePath, Message: message}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func matches(glob string, files []string) bool {
	for _, file := range files {
		if matched, _ := path.Match(glob, file); matched {
			return true
		}
	}
	return false
}

func selectFiles(globs, files []string) []string {
	var selected []string
	for _, file := range files {
		for _, glob := range globs {
			if matched, _ := path.Match(glob, file); matched {
				selected = append(selected, file)
				break
			}
		}
	}
	return selected
}

func fileSet(files []string) map[string]struct{} {
	set := make(map[string]struct{}, len(files))
	for _, file := range files {
		set[file] = struct{}{}
	}
	return set
}

func checkSums(root *os.Root, manifest string, files []string, oversized map[string]bool, digests *digestCache) []report.Finding {
	data, err := readRegularLimited(root, manifest, maxChecksumManifestBytes)
	if errors.Is(err, errMetadataTooLarge) {
		return []report.Finding{fail(
			"checksums-size",
			manifest,
			fmt.Sprintf("checksum manifest exceeds %d bytes", maxChecksumManifestBytes),
		)}
	}
	if err != nil {
		return []report.Finding{fail("checksums", manifest, "checksum manifest is missing or not a regular file")}
	}

	knownFiles := fileSet(files)
	var findings []report.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	seen := make(map[string]bool)
	for scanner.Scan() {
		line++
		hashText, relative, ok := parseChecksumLine(scanner.Text())
		if !ok {
			findings = append(findings, fail("checksums", manifest, fmt.Sprintf("invalid line %d", line)))
			continue
		}
		clean, err := bundlepath.Normalize(relative)
		if err != nil {
			findings = append(findings, fail("checksums", relative, "path escapes bundle"))
			continue
		}
		if seen[clean] {
			findings = append(findings, fail("checksums", relative, "duplicate normalized path in checksum manifest"))
			continue
		}
		seen[clean] = true
		if _, ok := knownFiles[clean]; !ok {
			findings = append(findings, fail("checksums", relative, "listed file is missing or not a regular file"))
			continue
		}
		if oversized[clean] {
			findings = append(findings, fail("checksums", relative, "listed file exceeds maxFileSize and was not hashed"))
			continue
		}

		want, decodeErr := hex.DecodeString(hashText)
		got, hashErr := digests.sum(clean)
		if hashErr != nil {
			findings = append(findings, fail("checksums", relative, "listed file cannot be read safely"))
			continue
		}
		if decodeErr != nil || !equal(want, got[:]) {
			findings = append(findings, fail("checksums", relative, "SHA-256 mismatch"))
		}
	}
	if err := scanner.Err(); err != nil {
		findings = append(findings, fail("checksums", manifest, "checksum manifest contains an oversized line"))
	}
	for _, relative := range files {
		if relative != manifest && !seen[relative] {
			findings = append(findings, fail("checksums", relative, "file is not listed in checksum manifest"))
		}
	}
	return findings
}

func parseChecksumLine(line string) (hash, filename string, ok bool) {
	line = strings.TrimSuffix(line, "\r")
	if len(line) < sha256.Size*2+3 || line[sha256.Size*2] != ' ' {
		return "", "", false
	}
	marker := line[sha256.Size*2+1]
	if marker != ' ' && marker != '*' {
		return "", "", false
	}
	filename = line[sha256.Size*2+2:]
	if filename == "" {
		return "", "", false
	}
	return line[:sha256.Size*2], filename, true
}

func openRegular(root *os.Root, relative string) (*os.File, int64, error) {
	name := filepath.FromSlash(relative)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, 0, errors.New("not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, 0, errors.New("file changed while opening")
	}
	return file, after.Size(), nil
}

func readRegularLimited(root *os.Root, relative string, limit int64) ([]byte, error) {
	file, size, err := openRegular(root, relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if size > limit {
		return nil, errMetadataTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errMetadataTooLarge
	}
	return data, nil
}

func hashRegular(root *os.Root, relative string) ([sha256.Size]byte, error) {
	file, _, err := openRegular(root, relative)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum, nil
}

type digestResult struct {
	sum [sha256.Size]byte
	err error
}

type digestCache struct {
	root   *os.Root
	values map[string]digestResult
}

func newDigestCache(root *os.Root) *digestCache {
	return &digestCache{root: root, values: make(map[string]digestResult)}
}

func (c *digestCache) sum(relative string) ([sha256.Size]byte, error) {
	if cached, ok := c.values[relative]; ok {
		return cached.sum, cached.err
	}
	sum, err := hashRegular(c.root, relative)
	c.values[relative] = digestResult{sum: sum, err: err}
	return sum, err
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

func checkSBOM(root *os.Root, files []string, oversized map[string]bool, sbomPolicy policy.SBOM) []report.Finding {
	selected := selectFiles(sbomPolicy.Globs, files)
	if (sbomPolicy.Required || len(sbomPolicy.Formats) > 0) && len(selected) == 0 {
		return []report.Finding{fail("sbom-required", "", "SBOM is required")}
	}

	var findings []report.Finding
	for _, file := range selected {
		if oversized[file] {
			findings = append(findings, fail("sbom-size", file, "SBOM exceeds maxFileSize and was not parsed"))
			continue
		}
		data, err := readRegularLimited(root, file, maxMetadataBytes)
		if errors.Is(err, errMetadataTooLarge) {
			findings = append(findings, fail(
				"sbom-size",
				file,
				fmt.Sprintf("SBOM exceeds %d bytes", maxMetadataBytes),
			))
			continue
		}
		if err != nil {
			findings = append(findings, fail("sbom-json", file, "SBOM file cannot be read safely"))
			continue
		}

		var document map[string]any
		if strictjson.Validate(data) != nil || json.Unmarshal(data, &document) != nil {
			findings = append(findings, fail("sbom-json", file, "invalid or ambiguous JSON"))
			continue
		}
		format := ""
		if document["bomFormat"] == "CycloneDX" {
			format = "cyclonedx"
			if version, ok := document["specVersion"].(string); !ok || version == "" {
				findings = append(findings, fail("sbom-cyclonedx", file, "specVersion must be a non-empty string"))
			}
		} else if _, exists := document["spdxVersion"]; exists {
			format = "spdx"
			if version, ok := document["spdxVersion"].(string); !ok || version == "" {
				findings = append(findings, fail("sbom-spdx", file, "spdxVersion must be a non-empty string"))
			}
			if identifier, ok := document["SPDXID"].(string); !ok || identifier == "" {
				findings = append(findings, fail("sbom-spdx", file, "SPDXID must be a non-empty string"))
			}
		} else {
			findings = append(findings, fail("sbom-format", file, "not CycloneDX or SPDX JSON"))
		}
		if len(sbomPolicy.Formats) > 0 && !contains(sbomPolicy.Formats, format) {
			findings = append(findings, fail("sbom-format", file, "format is not allowed"))
		}
	}
	return findings
}

type provenanceStatement struct {
	Subject   []provenanceSubject `json:"subject"`
	Predicate struct {
		Repository string `json:"repository"`
		Ref        string `json:"ref"`
		Workflow   string `json:"workflow"`
	} `json:"predicate"`
}

type provenanceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func checkProvenance(root *os.Root, files []string, oversized map[string]bool, digests *digestCache, provenancePolicy policy.Provenance) []report.Finding {
	selected := selectFiles(provenancePolicy.Globs, files)
	constraintsConfigured := provenancePolicy.Repository != "" || provenancePolicy.Ref != "" || provenancePolicy.Workflow != ""
	if (provenancePolicy.Required || constraintsConfigured) && len(selected) == 0 {
		return []report.Finding{fail("provenance-required", "", "provenance is required")}
	}

	knownFiles := fileSet(files)
	var findings []report.Finding
	covered := make(map[string]bool)
	for _, file := range selected {
		if oversized[file] {
			findings = append(findings, fail("provenance-size", file, "provenance exceeds maxFileSize and was not parsed"))
			continue
		}
		data, err := readRegularLimited(root, file, maxMetadataBytes)
		if errors.Is(err, errMetadataTooLarge) {
			findings = append(findings, fail(
				"provenance-size",
				file,
				fmt.Sprintf("provenance exceeds %d bytes", maxMetadataBytes),
			))
			continue
		}
		if err != nil {
			findings = append(findings, fail("provenance-json", file, "provenance file cannot be read safely"))
			continue
		}
		if err := strictjson.Validate(data); err != nil {
			findings = append(findings, fail("provenance-json", file, "invalid or ambiguous JSON: "+err.Error()))
			continue
		}
		if err := validateProvenanceFieldNames(data); err != nil {
			findings = append(findings, fail("provenance-json", file, "invalid or ambiguous JSON: "+err.Error()))
			continue
		}

		var statement provenanceStatement
		if err := json.Unmarshal(data, &statement); err != nil {
			findings = append(findings, fail("provenance-json", file, "invalid provenance schema: "+err.Error()))
			continue
		}
		if len(statement.Subject) == 0 {
			findings = append(findings, fail("provenance-subject", file, "subject is required"))
		}
		seenSubjects := make(map[string]struct{}, len(statement.Subject))
		for _, subject := range statement.Subject {
			clean, err := bundlepath.Normalize(subject.Name)
			if err != nil {
				findings = append(findings, fail("provenance-subject", file, "subject path escapes bundle"))
				continue
			}
			if _, duplicate := seenSubjects[clean]; duplicate {
				findings = append(findings, fail("provenance-subject", file, "duplicate normalized subject path"))
				continue
			}
			seenSubjects[clean] = struct{}{}
			if _, ok := knownFiles[clean]; !ok {
				findings = append(findings, fail("provenance-subject", file, "subject file is missing or not regular"))
				continue
			}
			if oversized[clean] {
				findings = append(findings, fail("provenance-subject", file, "subject exceeds maxFileSize and was not hashed"))
				continue
			}
			want, ok := subject.Digest["sha256"]
			if !ok || len(want) != sha256.Size*2 {
				findings = append(findings, fail("provenance-subject", file, "subject SHA-256 digest is missing or invalid"))
				continue
			}
			sum, err := digests.sum(clean)
			if err != nil {
				findings = append(findings, fail("provenance-subject", file, "subject file cannot be read safely"))
				continue
			}
			if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
				findings = append(findings, fail("provenance-subject", file, "subject SHA-256 mismatch"))
				continue
			}
			covered[clean] = true
		}

		constraints := []struct {
			name string
			got  string
			want string
		}{
			{"repository", statement.Predicate.Repository, provenancePolicy.Repository},
			{"ref", statement.Predicate.Ref, provenancePolicy.Ref},
			{"workflow", statement.Predicate.Workflow, provenancePolicy.Workflow},
		}
		for _, constraint := range constraints {
			if constraint.want != "" && constraint.got != constraint.want {
				findings = append(findings, fail(
					"provenance-constraint",
					file,
					constraint.name+" constraint not satisfied",
				))
			}
		}
	}
	for _, required := range provenancePolicy.RequiredSubjects {
		clean, err := bundlepath.Normalize(required)
		if err == nil && !covered[clean] {
			findings = append(findings, fail(
				"provenance-coverage",
				clean,
				"required subject is not covered by valid provenance",
			))
		}
	}
	return findings
}

func validateProvenanceFieldNames(data []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	if err := rejectCaseAliases(document, "subject", "predicate"); err != nil {
		return err
	}
	if raw, ok := document["predicate"]; ok {
		var predicate map[string]json.RawMessage
		if err := json.Unmarshal(raw, &predicate); err == nil {
			if err := rejectCaseAliases(predicate, "repository", "ref", "workflow"); err != nil {
				return err
			}
		}
	}
	if raw, ok := document["subject"]; ok {
		var subjects []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &subjects); err == nil {
			for _, subject := range subjects {
				if err := rejectCaseAliases(subject, "name", "digest"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectCaseAliases(document map[string]json.RawMessage, exactNames ...string) error {
	for name := range document {
		for _, exact := range exactNames {
			if name != exact && strings.EqualFold(name, exact) {
				return fmt.Errorf("field %q must be spelled %q", name, exact)
			}
		}
	}
	return nil
}
