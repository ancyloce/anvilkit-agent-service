package main

// document.go is order-preserving JSON reading and rewriting for the approved
// release and definition stores. The stores are reviewed documents whose
// digests are taken over their exact bytes: a rewrite must change exactly the
// members it means to change and nothing about the surrounding formatting, so
// parsing keeps member order and encoding reproduces the repository's
// two-space-indented layout byte for byte.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type nodeKind int

const (
	scalarNode nodeKind = iota
	objectNode
	arrayNode
)

// documentNode is one JSON value with its object members in document order.
type documentNode struct {
	kind    nodeKind
	scalar  json.RawMessage
	members []documentMember
	items   []*documentNode
}

type documentMember struct {
	key   string
	value *documentNode
}

// parseDocument reads exactly one JSON document, preserving member order.
func parseDocument(raw []byte) (*documentNode, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing content after the document")
	}
	return value, nil
}

func parseValue(decoder *json.Decoder) (*documentNode, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read value: %w", err)
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			object := &documentNode{kind: objectNode}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("read member key: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object member key is not a string")
				}
				value, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				object.members = append(object.members, documentMember{key: key, value: value})
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("read object end: %w", err)
			}
			return object, nil
		case '[':
			array := &documentNode{kind: arrayNode}
			for decoder.More() {
				value, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				array.items = append(array.items, value)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("read array end: %w", err)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", typed)
		}
	case string:
		return &documentNode{kind: scalarNode, scalar: encodeString(typed)}, nil
	case json.Number:
		return &documentNode{kind: scalarNode, scalar: json.RawMessage(typed.String())}, nil
	case bool:
		if typed {
			return &documentNode{kind: scalarNode, scalar: json.RawMessage("true")}, nil
		}
		return &documentNode{kind: scalarNode, scalar: json.RawMessage("false")}, nil
	case nil:
		return &documentNode{kind: scalarNode, scalar: json.RawMessage("null")}, nil
	default:
		return nil, fmt.Errorf("unexpected token %v", token)
	}
}

// encodeString encodes one string the way the stores are written: standard
// JSON escaping without HTML escaping.
func encodeString(value string) json.RawMessage {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		// A Go string always encodes; this branch is unreachable but errcheck
		// deserves an answer.
		return json.RawMessage(`""`)
	}
	return json.RawMessage(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
}

// encodedBytes renders the document with the repository's formatting: two-space
// indentation, a space after each colon, and a trailing newline.
func (n *documentNode) encodedBytes() []byte {
	var buffer bytes.Buffer
	n.encode(&buffer, 0)
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

func (n *documentNode) encode(buffer *bytes.Buffer, depth int) {
	switch n.kind {
	case scalarNode:
		buffer.Write(n.scalar)
	case objectNode:
		if len(n.members) == 0 {
			buffer.WriteString("{}")
			return
		}
		buffer.WriteString("{\n")
		for index, entry := range n.members {
			buffer.WriteString(strings.Repeat("  ", depth+1))
			buffer.Write(encodeString(entry.key))
			buffer.WriteString(": ")
			entry.value.encode(buffer, depth+1)
			if index < len(n.members)-1 {
				buffer.WriteString(",")
			}
			buffer.WriteString("\n")
		}
		buffer.WriteString(strings.Repeat("  ", depth))
		buffer.WriteString("}")
	case arrayNode:
		if len(n.items) == 0 {
			buffer.WriteString("[]")
			return
		}
		buffer.WriteString("[\n")
		for index, item := range n.items {
			buffer.WriteString(strings.Repeat("  ", depth+1))
			item.encode(buffer, depth+1)
			if index < len(n.items)-1 {
				buffer.WriteString(",")
			}
			buffer.WriteString("\n")
		}
		buffer.WriteString(strings.Repeat("  ", depth))
		buffer.WriteString("]")
	}
}

// child descends through object members by key.
func (n *documentNode) child(path ...string) (*documentNode, error) {
	current := n
	for _, key := range path {
		if current.kind != objectNode {
			return nil, fmt.Errorf("member %q: not an object", key)
		}
		var next *documentNode
		for _, entry := range current.members {
			if entry.key == key {
				next = entry.value
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("member %q: not present", key)
		}
		current = next
	}
	return current, nil
}

// stringAt reads one string member.
func (n *documentNode) stringAt(path ...string) (string, error) {
	value, err := n.child(path...)
	if err != nil {
		return "", err
	}
	if value.kind != scalarNode {
		return "", fmt.Errorf("member %q: not a scalar", strings.Join(path, "."))
	}
	var decoded string
	if err := json.Unmarshal(value.scalar, &decoded); err != nil {
		return "", fmt.Errorf("member %q: %w", strings.Join(path, "."), err)
	}
	return decoded, nil
}

// setString replaces one existing string member.
func (n *documentNode) setString(value string, path ...string) error {
	target, err := n.child(path...)
	if err != nil {
		return err
	}
	if target.kind != scalarNode {
		return fmt.Errorf("member %q: not a scalar", strings.Join(path, "."))
	}
	target.scalar = encodeString(value)
	return nil
}

// upsertString sets one string member on an object, appending the member when
// it is not already present.
func (n *documentNode) upsertString(key, value string, path ...string) error {
	object, err := n.child(path...)
	if err != nil {
		return err
	}
	if object.kind != objectNode {
		return fmt.Errorf("member %q: not an object", strings.Join(path, "."))
	}
	for index := range object.members {
		if object.members[index].key == key {
			object.members[index].value = &documentNode{kind: scalarNode, scalar: encodeString(value)}
			return nil
		}
	}
	object.members = append(object.members, documentMember{key: key, value: &documentNode{kind: scalarNode, scalar: encodeString(value)}})
	return nil
}

// removeMember deletes one object member when present.
func (n *documentNode) removeMember(key string, path ...string) error {
	object, err := n.child(path...)
	if err != nil {
		return err
	}
	if object.kind != objectNode {
		return fmt.Errorf("member %q: not an object", strings.Join(path, "."))
	}
	kept := object.members[:0]
	for _, entry := range object.members {
		if entry.key != key {
			kept = append(kept, entry)
		}
	}
	object.members = kept
	return nil
}
