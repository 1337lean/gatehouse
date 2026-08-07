package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHumanReportQuotesHostilePaths(t *testing.T) {
	result := Result{Findings: []Finding{{Rule: "test", Path: "file\n\x1b[31m", Message: "rejected"}}}
	var output bytes.Buffer
	if err := Write(&output, "human", result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "file\n") || !strings.Contains(output.String(), `"file\n\x1b[31m"`) {
		t.Fatalf("unsafe human output %q", output.String())
	}
}

func TestSARIFOmitEscapingArtifactLocations(t *testing.T) {
	result := Result{Findings: []Finding{
		{Rule: "escape", Path: "../outside", Message: "rejected"},
		{Rule: "safe", Path: "dir/file name.json", Message: "rejected"},
	}}
	var output bytes.Buffer
	if err := Write(&output, "sarif", result); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	runs := document["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if _, exists := results[0].(map[string]any)["locations"]; exists {
		t.Fatal("escaping path was emitted as a SARIF artifact location")
	}
	location := results[1].(map[string]any)["locations"].([]any)[0].(map[string]any)
	physical := location["physicalLocation"].(map[string]any)
	artifact := physical["artifactLocation"].(map[string]any)
	if artifact["uri"] != "dir/file%20name.json" {
		t.Fatalf("artifact URI = %#v", artifact["uri"])
	}
}

func TestJSONOutputIsStable(t *testing.T) {
	result := Result{Valid: false, Findings: []Finding{{Rule: "required", Path: "README.md", Message: "missing"}}}
	var output bytes.Buffer
	if err := Write(&output, "json", result); err != nil {
		t.Fatal(err)
	}
	const want = `{"valid":false,"findings":[{"rule":"required","path":"README.md","message":"missing"}]}` + "\n"
	if output.String() != want {
		t.Fatalf("JSON output changed:\n got: %q\nwant: %q", output.String(), want)
	}
}

func TestSARIFOutputIsStable(t *testing.T) {
	result := Result{Valid: false, Findings: []Finding{{Rule: "required", Path: "README.md", Message: "missing"}}}
	var output bytes.Buffer
	if err := Write(&output, "sarif", result); err != nil {
		t.Fatal(err)
	}
	const want = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"results":[{"ruleId":"required","level":"error","message":{"text":"missing"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"README.md"}}}]}],"tool":{"driver":{"informationUri":"https://github.com/1337lean/gatehouse","name":"Gatehouse"}}}],"version":"2.1.0"}` + "\n"
	if output.String() != want {
		t.Fatalf("SARIF output changed:\n got: %q\nwant: %q", output.String(), want)
	}
}
