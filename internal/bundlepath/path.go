package bundlepath

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// Normalize validates a portable, bundle-relative path and returns its
// slash-separated lexical normal form. The path is not resolved on disk.
func Normalize(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("path contains NUL")
	}
	// Bundle metadata uses slash-separated paths. Treat backslashes as
	// separators too so a manifest cannot become unsafe on another OS.
	portable := strings.ReplaceAll(name, `\`, "/")
	for _, character := range portable {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("path contains a control character")
		}
	}
	if strings.ContainsRune(portable, ':') {
		return "", fmt.Errorf("path contains a colon")
	}
	if strings.HasPrefix(portable, "/") || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || (len(portable) >= 2 && portable[1] == ':' && ((portable[0] >= 'a' && portable[0] <= 'z') || (portable[0] >= 'A' && portable[0] <= 'Z'))) {
		return "", fmt.Errorf("path is absolute")
	}
	clean := path.Clean(portable)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes bundle")
	}
	return clean, nil
}
