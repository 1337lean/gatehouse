package bundlepath

import "testing"

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"..artifact":      "..artifact",
		"dir/../artifact": "artifact",
		"dir\\file":       "dir/file",
	}
	for input, want := range tests {
		got, err := Normalize(input)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"../artifact", "dir/../../artifact", "/artifact", `C:\artifact`, "name:stream", "line\nfeed", ""} {
		if _, err := Normalize(input); err == nil {
			t.Errorf("Normalize(%q) succeeded", input)
		}
	}
}
