package strictjson

import "testing"

func TestValidateRejectsAmbiguousJSON(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"key":1,"key":2}`),
		[]byte(`{"nested":{"key":1,"key":2}}`),
		[]byte("{\"key\":\"\xff\"}"),
		[]byte(`{"key":1} {"key":2}`),
	}
	for _, data := range tests {
		if err := Validate(data); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
}

func TestValidateAcceptsWellFormedJSON(t *testing.T) {
	if err := Validate([]byte(`{"array":[1,{"nested":true}],"unicode":"✓"}`)); err != nil {
		t.Fatal(err)
	}
}
