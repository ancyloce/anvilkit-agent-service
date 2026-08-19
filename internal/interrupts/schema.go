package interrupts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// BoundSchemaValidator implements the deliberately small InputRequest
// response-schema profile used before the Contract Runtime boundary. It is
// fail-closed and rejects unsupported schema keywords.
type BoundSchemaValidator struct{}

func (BoundSchemaValidator) Validate(_ context.Context, schemaBytes, valueBytes json.RawMessage) error {
	var schema struct {
		Type                 string                     `json:"type"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := strictDecode(schemaBytes, &schema); err != nil {
		return fmt.Errorf("decode response schema: %w", err)
	}
	if schema.Type != "object" || schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		return fmt.Errorf("response schema must be a closed object")
	}
	var value map[string]json.RawMessage
	if err := strictDecode(valueBytes, &value); err != nil || value == nil {
		return fmt.Errorf("response must be one object")
	}
	for _, name := range schema.Required {
		if _, ok := value[name]; !ok {
			return fmt.Errorf("required field %s is absent", name)
		}
	}
	for name, raw := range value {
		property, ok := schema.Properties[name]
		if !ok {
			return fmt.Errorf("unknown field %s", name)
		}
		var rule struct {
			Type      string `json:"type"`
			MaxLength int    `json:"maxLength,omitempty"`
		}
		if err := strictDecode(property, &rule); err != nil {
			return fmt.Errorf("decode rule %s: %w", name, err)
		}
		if err := validatePrimitive(raw, rule.Type, rule.MaxLength); err != nil {
			return fmt.Errorf("field %s: %w", name, err)
		}
	}
	return nil
}

func validatePrimitive(raw json.RawMessage, kind string, maximum int) error {
	switch kind {
	case "string":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("must be string")
		}
		if maximum > 0 && len(value) > maximum {
			return fmt.Errorf("exceeds maxLength")
		}
	case "integer":
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		number, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("must be integer")
		}
		if _, err := number.Int64(); err != nil {
			return fmt.Errorf("must be integer")
		}
	case "boolean":
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("must be boolean")
		}
	default:
		return fmt.Errorf("unsupported primitive type %q", kind)
	}
	return nil
}

func strictDecode(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return fmt.Errorf("JSON is empty or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
