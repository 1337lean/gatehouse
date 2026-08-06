package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

type Finding struct {
	Rule    string `json:"rule"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Valid    bool      `json:"valid"`
	Findings []Finding `json:"findings"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func Write(w io.Writer, format string, r Result) error {
	switch format {
	case "human":
		return writeHuman(w, r)
	case "json":
		return json.NewEncoder(w).Encode(r)
	case "sarif":
		return writeSARIF(w, r)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func writeHuman(w io.Writer, r Result) error {
	if r.Valid {
		_, err := fmt.Fprintln(w, "PASS: bundle satisfies policy")
		return err
	}
	for _, finding := range r.Findings {
		var err error
		if finding.Path != "" {
			_, err = fmt.Fprintf(w, "FAIL [%s] %q: %s\n", finding.Rule, finding.Path, finding.Message)
		} else {
			_, err = fmt.Fprintf(w, "FAIL [%s] %s\n", finding.Rule, finding.Message)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func writeSARIF(w io.Writer, r Result) error {
	results := make([]sarifResult, 0, len(r.Findings))
	for _, finding := range r.Findings {
		item := sarifResult{
			RuleID:  finding.Rule,
			Level:   "error",
			Message: sarifMessage{Text: finding.Message},
		}
		if uri, ok := safeArtifactURI(finding.Path); ok {
			var location sarifLocation
			location.PhysicalLocation.ArtifactLocation.URI = uri
			item.Locations = []sarifLocation{location}
		}
		results = append(results, item)
	}
	document := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "Gatehouse",
				"informationUri": "https://github.com/1337lean/gatehouse",
			}},
			"results": results,
		}},
	}
	return json.NewEncoder(w).Encode(document)
}

func safeArtifactURI(name string) (string, bool) {
	portable := strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(portable)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	for _, character := range clean {
		if character < 0x20 || character == 0x7f {
			return "", false
		}
	}
	escaped := (&url.URL{Path: clean}).EscapedPath()
	if strings.Contains(strings.SplitN(clean, "/", 2)[0], ":") {
		escaped = "./" + escaped
	}
	return escaped, true
}
