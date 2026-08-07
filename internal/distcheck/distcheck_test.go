package distcheck

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var fixtureEntries = map[string][]byte{
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

func TestVerifyRejectsInvalidRequiredEntries(t *testing.T) {
	t.Run("wrong executable target", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "darwin", arch: "arm64"}
		entries := archiveEntries(selected, false)
		entries["gatehouse"] = fakeExecutable(target{os: "darwin", arch: "amd64"})
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "darwin/arm64 binary") {
			t.Fatalf("wrong-target executable error = %v", err)
		}
	})

	t.Run("empty required asset", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "arm64"}
		entries := archiveEntries(selected, false)
		entries["README.md"] = nil
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), `"README.md" is empty`) {
			t.Fatalf("empty asset error = %v", err)
		}
	})

	t.Run("zip CRC failure", func(t *testing.T) {
		directory, names := writeDistribution(t)
		name := archiveName("1.2.3", target{os: "windows", arch: "amd64"})
		archivePath := filepath.Join(directory, name)
		data, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		index := bytes.Index(data, fixtureEntries["README.md"])
		if index < 0 {
			t.Fatal("stored README data not found in ZIP fixture")
		}
		data[index] ^= 0xff
		if err := os.WriteFile(archivePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		writeChecksums(t, directory, names)
		if err := Verify(directory, false); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("ZIP CRC error = %v", err)
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
		name := archiveName(version, target)
		entries := archiveEntries(target, omitPolicy)
		archivePath := filepath.Join(directory, name)
		writeArchive(t, archivePath, target, entries)
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func archiveName(version string, target target) string {
	extension := ".tar.gz"
	if target.os == "windows" {
		extension = ".zip"
	}
	return fmt.Sprintf("gatehouse_%s_%s_%s%s", version, target.os, target.arch, extension)
}

func archiveEntries(target target, omitPolicy bool) map[string][]byte {
	entries := make(map[string][]byte, len(fixtureEntries)+1)
	for entryName, contents := range fixtureEntries {
		if omitPolicy && entryName == "docs/policy.md" {
			continue
		}
		entries[entryName] = contents
	}
	executableName := "gatehouse"
	if target.os == "windows" {
		executableName += ".exe"
	}
	entries[executableName] = fakeExecutable(target)
	return entries
}

func writeArchive(t *testing.T, name string, target target, entries map[string][]byte) {
	t.Helper()
	if target.os == "windows" {
		writeZip(t, name, entries)
	} else {
		writeTarGzip(t, name, entries)
	}
}

func fakeExecutable(target target) []byte {
	switch target.os {
	case "linux":
		data := make([]byte, 64)
		copy(data, "\x7fELF")
		data[4], data[5], data[6] = 2, 1, 1
		binary.LittleEndian.PutUint16(data[16:18], 2)
		machine := uint16(62)
		if target.arch == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(data[18:20], machine)
		binary.LittleEndian.PutUint32(data[20:24], 1)
		binary.LittleEndian.PutUint16(data[52:54], 64)
		return data
	case "darwin":
		data := make([]byte, 32)
		binary.LittleEndian.PutUint32(data[:4], 0xfeedfacf)
		machine := uint32(0x01000007)
		if target.arch == "arm64" {
			machine = 0x0100000c
		}
		binary.LittleEndian.PutUint32(data[4:8], machine)
		binary.LittleEndian.PutUint32(data[12:16], 2)
		return data
	case "windows":
		data := make([]byte, 328)
		copy(data, "MZ")
		binary.LittleEndian.PutUint32(data[0x3c:0x40], 64)
		copy(data[64:68], "PE\x00\x00")
		machine := uint16(0x8664)
		if target.arch == "arm64" {
			machine = 0xaa64
		}
		binary.LittleEndian.PutUint16(data[68:70], machine)
		binary.LittleEndian.PutUint16(data[84:86], 240)
		binary.LittleEndian.PutUint16(data[86:88], 0x0002)
		binary.LittleEndian.PutUint16(data[88:90], 0x020b)
		binary.LittleEndian.PutUint32(data[196:200], 16)
		return data
	default:
		return []byte("invalid")
	}
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
		header := &zip.FileHeader{Name: entryName, Method: zip.Store}
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
