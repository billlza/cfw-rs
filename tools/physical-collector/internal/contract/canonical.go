package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := marshalWithoutHTMLEscaping(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON input: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("decode canonical JSON input: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("canonical JSON input has trailing data")
	}
	var output []byte
	output, err = appendCanonical(output, generic)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func marshalWithoutHTMLEscaping(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func appendCanonical(output []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return append(output, "null"...), nil
	case bool:
		return strconv.AppendBool(output, typed), nil
	case string:
		return appendJSONString(output, typed), nil
	case json.Number:
		text := typed.String()
		if !canonicalInteger(text) {
			return nil, fmt.Errorf("canonical JSON rejects non-integer number %q", text)
		}
		return append(output, text...), nil
	case []any:
		output = append(output, '[')
		for index, nested := range typed {
			if index != 0 {
				output = append(output, ',')
			}
			var err error
			output, err = appendCanonical(output, nested)
			if err != nil {
				return nil, err
			}
		}
		return append(output, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output = append(output, '{')
		for index, key := range keys {
			if index != 0 {
				output = append(output, ',')
			}
			output = appendJSONString(output, key)
			output = append(output, ':')
			var err error
			output, err = appendCanonical(output, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(output, '}'), nil
	default:
		return nil, fmt.Errorf("unsupported canonical JSON type %T", value)
	}
}

func appendJSONString(output []byte, value string) []byte {
	encoded := strconv.AppendQuote(nil, value)
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003c`), []byte("<"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003e`), []byte(">"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u0026`), []byte("&"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2028`), []byte("\u2028"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2029`), []byte("\u2029"))
	return append(output, encoded...)
}

func canonicalInteger(value string) bool {
	if value == "0" {
		return true
	}
	if strings.HasPrefix(value, "-") {
		value = strings.TrimPrefix(value, "-")
	}
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
