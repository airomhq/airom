package spdx3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Serializer handles deterministic JSON-LD canonicalization and writing for SPDX 3.0.1.
type Serializer struct {
	NamespacePrefix string
	Indent          string
}

// NewSerializer initializes a Serializer with default 2-space indentation and canonical namespace.
func NewSerializer(docNamespace string) *Serializer {
	if docNamespace == "" {
		docNamespace = "https://spdx.org/spdxdocs/airom"
	}
	docNamespace = strings.TrimRight(docNamespace, "/")
	return &Serializer{
		NamespacePrefix: docNamespace,
		Indent:          "  ",
	}
}

// Serialize sorts the @graph elements deterministically and writes formatted JSON-LD to w.
func (s *Serializer) Serialize(w io.Writer, doc *Document) error {
	if doc == nil {
		return fmt.Errorf("spdx3 serializer: nil document")
	}

	if doc.Context == "" {
		doc.Context = ContextIRI
	}

	// Sort @graph elements deterministically by @id.
	sort.Slice(doc.Graph, func(i, j int) bool {
		idI := doc.Graph[i].GetSpdxID()
		idJ := doc.Graph[j].GetSpdxID()
		if idI == idJ {
			return doc.Graph[i].GetType() < doc.Graph[j].GetType()
		}
		return idI < idJ
	})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", s.Indent)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("spdx3 serializer encode: %w", err)
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// CanonicalID mints a canonical URI for an element given its logical identifier.
func (s *Serializer) CanonicalID(kind, id string) string {
	cleanID := strings.TrimPrefix(id, "airom:")
	cleanID = strings.ReplaceAll(cleanID, ":", "_")
	cleanID = strings.ReplaceAll(cleanID, "/", "_")
	return fmt.Sprintf("%s/%s/%s", s.NamespacePrefix, kind, cleanID)
}
