package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxDepth is encoding/json's nesting limit.
const maxDepth = 10000

// validateJSON returns an error unless data is exactly one UTF-8 JSON
// document with no duplicate object keys and no unpaired surrogate escapes.
// encoding/json would keep the last duplicate and map unpaired surrogates to
// U+FFFD, so two parsers could read different manifests from the same bytes.
func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON must be UTF-8")
	}
	if err := validateUnicodeEscapes(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value func(depth int) error
	value = func(depth int) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if depth >= maxDepth {
			return fmt.Errorf("JSON exceeds nesting depth %d", maxDepth)
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if seen[k] {
					return errors.New("duplicate JSON object key")
				}
				seen[k] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(0); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("JSON document is empty or truncated")
		}
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}

func validateUnicodeEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			break
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return errors.New("unpaired Unicode surrogate")
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return errors.New("unpaired Unicode surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return errors.New("unpaired Unicode surrogate")
			}
			i += 6
		}
	}
	return nil
}
