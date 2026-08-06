package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Validate rejects malformed JSON, trailing values, and duplicate object keys
// at every nesting level.
func Validate(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON is not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := value(d); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing data")
		}
		return err
	}
	return nil
}

func value(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for d.More() {
			tok, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := tok.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, ok := seen[key]; ok {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := value(d); err != nil {
				return err
			}
		}
		_, err := d.Token()
		return err
	case '[':
		for d.More() {
			if err := value(d); err != nil {
				return err
			}
		}
		_, err := d.Token()
		return err
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}
