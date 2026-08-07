// Package distcheck verifies that a Gatehouse distribution is complete and
// internally consistent before any artifact is published.
package distcheck

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxChecksumBytes  = 1 << 20
	maxArchiveEntries = 1_000
	maxEntryBytes     = 256 << 20
)

type target struct {
	os   string
	arch string
}

var expectedTargets = []target{
	{os: "darwin", arch: "amd64"},
	{os: "darwin", arch: "arm64"},
	{os: "linux", arch: "amd64"},
	{os: "linux", arch: "arm64"},
	{os: "windows", arch: "amd64"},
	{os: "windows", arch: "arm64"},
}

type archive struct {
	name    string
	path    string
	target  target
	version string
}

// Verify checks the complete release matrix, archive contents, and checksums.
// When smoke is true, the executable for the current host target is also run.
func Verify(directory string, smoke bool) error {
	archives, version, err := discoverArchives(directory)
	if err != nil {
		return err
	}
	if err := verifyChecksums(directory, archives); err != nil {
		return err
	}

	smoked := !smoke
	for _, item := range archives {
		executable, err := inspectArchive(item)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", item.name, err)
		}
		if smoke && item.target.os == runtime.GOOS && item.target.arch == runtime.GOARCH {
			if err := smokeExecutable(executable, version); err != nil {
				return fmt.Errorf("smoke %s: %w", item.name, err)
			}
			smoked = true
		}
	}
	if !smoked {
		return fmt.Errorf("no archive can run on verifier host %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

func discoverArchives(directory string) ([]archive, string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, "", fmt.Errorf("read distribution: %w", err)
	}
	want := make(map[target]bool, len(expectedTargets))
	for _, expected := range expectedTargets {
		want[expected] = true
	}
	seen := make(map[target]bool, len(expectedTargets))
	var archives []archive
	version := ""
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".tar.gz") && !strings.HasSuffix(entry.Name(), ".zip")) {
			continue
		}
		item, ok := parseArchiveName(directory, entry.Name())
		if !ok || !want[item.target] {
			return nil, "", fmt.Errorf("unexpected release archive %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, "", fmt.Errorf("inspect %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("release archive %q is not a regular file", entry.Name())
		}
		if seen[item.target] {
			return nil, "", fmt.Errorf("duplicate release target %s/%s", item.target.os, item.target.arch)
		}
		seen[item.target] = true
		if version == "" {
			version = item.version
		} else if item.version != version {
			return nil, "", fmt.Errorf("archive %q has version %q, want %q", item.name, item.version, version)
		}
		archives = append(archives, item)
	}
	for _, expected := range expectedTargets {
		if !seen[expected] {
			return nil, "", fmt.Errorf("missing release archive for %s/%s", expected.os, expected.arch)
		}
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].name < archives[j].name })
	return archives, version, nil
}

func parseArchiveName(directory, name string) (archive, bool) {
	if !strings.HasPrefix(name, "gatehouse_") {
		return archive{}, false
	}
	for _, candidate := range expectedTargets {
		extension := ".tar.gz"
		if candidate.os == "windows" {
			extension = ".zip"
		}
		suffix := "_" + candidate.os + "_" + candidate.arch + extension
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		version := strings.TrimSuffix(strings.TrimPrefix(name, "gatehouse_"), suffix)
		if version == "" {
			return archive{}, false
		}
		return archive{name: name, path: filepath.Join(directory, name), target: candidate, version: version}, true
	}
	return archive{}, false
}

func verifyChecksums(directory string, archives []archive) error {
	checksumPath := filepath.Join(directory, "checksums.txt")
	file, err := os.Open(checksumPath)
	if err != nil {
		return fmt.Errorf("open checksums.txt: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("inspect checksums.txt: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxChecksumBytes {
		file.Close()
		return errors.New("checksums.txt is not a bounded regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxChecksumBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read checksums.txt: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close checksums.txt: %w", closeErr)
	}
	if len(data) > maxChecksumBytes {
		return errors.New("checksums.txt exceeds verification limit")
	}

	want := make(map[string]archive, len(archives))
	for _, item := range archives {
		want[item.name] = item
	}
	seen := make(map[string]bool, len(archives))
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("checksums.txt line %d is invalid", lineNumber+1)
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("checksums.txt line %d has an invalid SHA-256", lineNumber+1)
		}
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) != name || name == "." {
			return fmt.Errorf("checksums.txt line %d has an unsafe name", lineNumber+1)
		}
		item, ok := want[name]
		if !ok {
			return fmt.Errorf("checksums.txt contains unexpected artifact %q", name)
		}
		if seen[name] {
			return fmt.Errorf("checksums.txt repeats artifact %q", name)
		}
		seen[name] = true
		actual, err := fileSHA256(item.path)
		if err != nil {
			return fmt.Errorf("hash %q: %w", name, err)
		}
		if !strings.EqualFold(fields[0], hex.EncodeToString(actual[:])) {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	for name := range want {
		if !seen[name] {
			return fmt.Errorf("checksums.txt is missing %q", name)
		}
	}
	return nil
}

func fileSHA256(name string) ([sha256.Size]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return [sha256.Size]byte{}, copyErr
	}
	if closeErr != nil {
		return [sha256.Size]byte{}, closeErr
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func inspectArchive(item archive) ([]byte, error) {
	required := map[string]bool{
		"LICENSE":                   false,
		"README.md":                 false,
		"docs/policy.md":            false,
		"testdata/demo-policy.json": false,
	}
	executableName := "gatehouse"
	if item.target.os == "windows" {
		executableName += ".exe"
	}
	required[executableName] = false

	var executable []byte
	visit := func(name string, mode os.FileMode, size int64, reader io.Reader) error {
		clean, err := cleanArchiveName(name)
		if err != nil {
			return err
		}
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("archive contains symbolic link %q", name)
		}
		if size < 0 || size > maxEntryBytes {
			return fmt.Errorf("archive entry %q has invalid size %d", name, size)
		}
		if _, ok := required[clean]; !ok {
			return nil
		}
		if required[clean] {
			return fmt.Errorf("archive repeats required entry %q", clean)
		}
		if !mode.IsRegular() {
			return fmt.Errorf("required archive entry %q is not regular", clean)
		}
		required[clean] = true
		if clean == executableName {
			executable, err = io.ReadAll(io.LimitReader(reader, maxEntryBytes+1))
			if err != nil {
				return err
			}
			if int64(len(executable)) != size {
				return fmt.Errorf("executable size changed while reading")
			}
		}
		return nil
	}

	var err error
	if item.target.os == "windows" {
		err = inspectZip(item.path, visit)
	} else {
		err = inspectTarGzip(item.path, visit)
	}
	if err != nil {
		return nil, err
	}
	for name, found := range required {
		if !found {
			return nil, fmt.Errorf("archive is missing %q", name)
		}
	}
	return executable, nil
}

func cleanArchiveName(name string) (string, error) {
	portable := strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "./")
	clean := path.Clean(portable)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func inspectTarGzip(name string, visit func(string, os.FileMode, int64, io.Reader) error) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tape := tar.NewReader(gzipReader)
	entries := 0
	for {
		header, err := tape.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxArchiveEntries {
			return errors.New("archive has too many entries")
		}
		if err := visit(header.Name, header.FileInfo().Mode(), header.Size, tape); err != nil {
			return err
		}
	}
}

func inspectZip(name string, visit func(string, os.FileMode, int64, io.Reader) error) error {
	reader, err := zip.OpenReader(name)
	if err != nil {
		return err
	}
	defer reader.Close()
	if len(reader.File) > maxArchiveEntries {
		return errors.New("archive has too many entries")
	}
	for _, entry := range reader.File {
		if entry.UncompressedSize64 > maxEntryBytes {
			return fmt.Errorf("archive entry %q exceeds size limit", entry.Name)
		}
		contents, err := entry.Open()
		if err != nil {
			return err
		}
		err = visit(entry.Name, entry.Mode(), int64(entry.UncompressedSize64), contents)
		closeErr := contents.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func smokeExecutable(data []byte, version string) error {
	if len(data) == 0 {
		return errors.New("executable is empty")
	}
	directory, err := os.MkdirTemp("", "gatehouse-release-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	name := filepath.Join(directory, "gatehouse")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(name, data, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, "version").CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("version command: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	if got := strings.TrimSpace(string(output)); got != version || got == "dev" {
		return fmt.Errorf("version output %q, want %q", got, version)
	}
	return nil
}
