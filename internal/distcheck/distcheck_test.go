package distcheck

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var fixtureEntries = map[string][]byte{
	"gatehouse":                 []byte("test executable"),
	"gatehouse.exe":             []byte("test executable"),
	"LICENSE":                   []byte("license"),
	"README.md":                 []byte("readme"),
	"docs/policy.md":            []byte("policy"),
	"testdata/demo-policy.json": []byte(`{"version":1}`),
}

func TestVerifyCompleteDistribution(t *testing.T) {
	directory, _ := writeDistribution(t)
	if err := Verify(directory, false); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsCorruptedNonFirstArchive(t *testing.T) {
	directory, names := writeDistribution(t)
	name := names[1]
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("corrupt"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corrupt archive error = %v", err)
	}
}

func TestVerifyRejectsIncompleteOrUnexpectedDistribution(t *testing.T) {
	t.Run("missing archive", func(t *testing.T) {
		directory, names := writeDistribution(t)
		if err := os.Remove(filepath.Join(directory, names[len(names)-1])); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "missing release archive") {
			t.Fatalf("missing archive error = %v", err)
		}
	})

	t.Run("unexpected archive", func(t *testing.T) {
		directory, _ := writeDistribution(t)
		if err := os.WriteFile(filepath.Join(directory, "gatehouse_1.2.3_linux_riscv64.tar.gz"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "unexpected release archive") {
			t.Fatalf("unexpected archive error = %v", err)
		}
	})

	t.Run("missing asset", func(t *testing.T) {
		directory := t.TempDir()
		names := writeArchives(t, directory, "1.2.3", true)
		writeChecksums(t, directory, names)
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), `missing "docs/policy.md"`) {
			t.Fatalf("missing asset error = %v", err)
		}
	})

	t.Run("unexpected checksum", func(t *testing.T) {
		directory, _ := writeDistribution(t)
		file, err := os.OpenFile(filepath.Join(directory, "checksums.txt"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(file, "%064x  extra.tar.gz\n", 0); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "unexpected artifact") {
			t.Fatalf("unexpected checksum error = %v", err)
		}
	})
}

func writeDistribution(t *testing.T) (string, []string) {
	t.Helper()
	directory := t.TempDir()
	names := writeArchives(t, directory, "1.2.3", false)
	writeChecksums(t, directory, names)
	return directory, names
}

func writeArchives(t *testing.T, directory, version string, omitPolicy bool) []string {
	t.Helper()
	var names []string
	for _, target := range expectedTargets {
		extension := ".tar.gz"
		if target.os == "windows" {
			extension = ".zip"
		}
		name := fmt.Sprintf("gatehouse_%s_%s_%s%s", version, target.os, target.arch, extension)
		entries := make(map[string][]byte, len(fixtureEntries))
		for entryName, contents := range fixtureEntries {
			if (target.os == "windows" && entryName == "gatehouse") || (target.os != "windows" && entryName == "gatehouse.exe") {
				continue
			}
			if omitPolicy && entryName == "docs/policy.md" {
				continue
			}
			entries[entryName] = contents
		}
		archivePath := filepath.Join(directory, name)
		if target.os == "windows" {
			writeZip(t, archivePath, entries)
		} else {
			writeTarGzip(t, archivePath, entries)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func writeTarGzip(t *testing.T, name string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tape := tar.NewWriter(gzipWriter)
	for _, entryName := range sortedEntryNames(entries) {
		contents := entries[entryName]
		mode := int64(0644)
		if entryName == "gatehouse" {
			mode = 0755
		}
		if err := tape.WriteHeader(&tar.Header{Name: entryName, Mode: mode, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tape.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tape.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, name string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	for _, entryName := range sortedEntryNames(entries) {
		header := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
		header.SetMode(0644)
		if entryName == "gatehouse.exe" {
			header.SetMode(0755)
		}
		entry, err := zipWriter.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(entries[entryName]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksums(t *testing.T, directory string, names []string) {
	t.Helper()
	file, err := os.Create(filepath.Join(directory, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		artifact, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, artifact); err != nil {
			artifact.Close()
			t.Fatal(err)
		}
		if err := artifact.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(file, "%x  %s\n", hash.Sum(nil), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func sortedEntryNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
