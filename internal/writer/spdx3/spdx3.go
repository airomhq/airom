package spdx3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/airomhq/airom/internal/writer"
	"github.com/airomhq/airom/pkg/airom"
)

func init() {
	writer.Register(FormatName, func(o writer.Options) writer.Writer { return New(o) })
}

// FormatName is the output format name for SPDX 3.0.1.
const FormatName = "spdx3"

// Writer implements writer.Writer for SPDX 3.0.1 JSON-LD output.
type Writer struct {
	opts writer.Options
}

// New constructs a new SPDX 3.0.1 Writer.
func New(opts writer.Options) *Writer {
	return &Writer{opts: opts}
}

// Format returns "spdx3".
func (w *Writer) Format() string {
	return FormatName
}

// Write projects *airom.Inventory into a validated SPDX 3.0.1 JSON-LD document.
func (w *Writer) Write(out io.Writer, inv *airom.Inventory) error {
	if inv == nil {
		return fmt.Errorf("spdx3 writer: nil inventory")
	}

	createdTime := inv.Timestamp
	if createdTime.IsZero() {
		createdTime = time.Now().UTC()
	}

	docHash := sha256.Sum256([]byte(inv.Source.Target + inv.Source.Kind + createdTime.Format(time.RFC3339)))
	docNamespace := fmt.Sprintf("https://spdx.org/spdxdocs/airom-%s", hex.EncodeToString(docHash[:8]))
	serializer := NewSerializer(docNamespace)

	agentID := serializer.CanonicalID("agent", "tool-airom")
	docID := serializer.CanonicalID("document", "root")

	creationInfo := &CreationInfo{
		SpecVersion:  SpecVersion,
		Created:      createdTime,
		CreatedBy:    []string{agentID},
		CreatedUsing: []string{fmt.Sprintf("airom-%s", inv.Tool.Version)},
		Comment:      "Generated deterministically by AIROM Enterprise Platform",
	}

	agent := &SoftwareAgent{
		Agent: Agent{
			BaseElement: BaseElement{
				Type:         "SoftwareAgent",
				SpdxID:       agentID,
				CreationInfo: creationInfo,
				Name:         "airom",
				Description:  "AI Bill of Materials Scanner & Enterprise Governance Platform",
			},
			AgentType: "Software",
		},
		SoftwareVersion: inv.Tool.Version,
	}

	docElem := &SpdxDocumentElement{
		BaseElement: BaseElement{
			Type:         "SpdxDocument",
			SpdxID:       docID,
			CreationInfo: creationInfo,
			Name:         fmt.Sprintf("AIBOM-%s", inv.Source.Target),
			Summary:      fmt.Sprintf("SPDX 3.0.1 AI Bill of Materials for %s (%s)", inv.Source.Target, inv.Source.Kind),
		},
		DataLicense: "https://spdx.org/licenses/CC0-1.0",
	}

	var elements []Element
	elements = append(elements, agent, docElem)

	// Build element map for relationship resolution
	compIDToSpdxID := make(map[airom.ID]string, len(inv.Components))
	var rootElementIDs []string

	// Sort components by ID for determinism
	comps := make([]airom.Component, len(inv.Components))
	copy(comps, inv.Components)
	sort.Slice(comps, func(i, j int) bool {
		return comps[i].ID < comps[j].ID
	})

	for _, c := range comps {
		spdxID := serializer.CanonicalID(string(c.Kind), string(c.ID))
		compIDToSpdxID[c.ID] = spdxID
		rootElementIDs = append(rootElementIDs, spdxID)

		providerStr := NoAssertion
		if v, ok := c.Provider.Value(); ok && v != "" {
			providerStr = v
		}

		verStr := NoAssertion
		if v, ok := c.Version.Value(); ok && v != "" {
			verStr = v
		}

		pkg := &Package{
			BaseElement: BaseElement{
				Type:         "Package",
				SpdxID:       spdxID,
				CreationInfo: creationInfo,
				Name:         c.Name,
				Summary:      fmt.Sprintf("%s (%s by %s)", c.Name, c.Kind, providerStr),
			},
			PackageVersion:   verStr,
			DownloadLocation: NoAssertion,
			PrimaryPurpose:   mapKindToPrimaryPurpose(c.Kind),
			SuppliedBy:       providerStr,
		}

		if c.PURL != "" {
			pkg.ExternalIdentifier = append(pkg.ExternalIdentifier, ExternalIdentifier{
				Type:                   "ExternalIdentifier",
				ExternalIdentifierType: "purl",
				Identifier:             c.PURL,
			})
		}

		for _, h := range c.Hashes {
			pkg.VerifiedUsing = append(pkg.VerifiedUsing, IntegrityMethod{
				Type:      "Hash",
				Algorithm: strings.ToLower(h.Alg),
				HashValue: h.Hex,
			})
		}

		if len(c.Licenses) > 0 {
			var licNames []string
			for _, lic := range c.Licenses {
				if lic.SPDXID != "" {
					licNames = append(licNames, lic.SPDXID)
				} else if lic.Expression != "" {
					licNames = append(licNames, lic.Expression)
				} else if lic.Name != "" {
					licNames = append(licNames, lic.Name)
				}
			}
			if len(licNames) > 0 {
				pkg.DeclaredLicense = strings.Join(licNames, " AND ")
				pkg.ConcludedLicense = pkg.DeclaredLicense
			} else {
				pkg.DeclaredLicense = NoAssertion
				pkg.ConcludedLicense = NoAssertion
			}
		} else {
			pkg.DeclaredLicense = NoAssertion
			pkg.ConcludedLicense = NoAssertion
		}

		elements = append(elements, pkg)
	}

	docElem.RootElement = rootElementIDs

	// Add Document Contains relationships
	if len(rootElementIDs) > 0 {
		relDocContains := &Relationship{
			BaseElement: BaseElement{
				Type:         "Relationship",
				SpdxID:       serializer.CanonicalID("relationship", "doc-contains-all"),
				CreationInfo: creationInfo,
			},
			From:             docID,
			To:               rootElementIDs,
			RelationshipType: RelContains,
			Completeness:     "known",
		}
		elements = append(elements, relDocContains)
	}

	// Add explicit component relationships
	for i, rel := range inv.Relationships {
		fromSpdx, okFrom := compIDToSpdxID[rel.From]
		toSpdx, okTo := compIDToSpdxID[rel.To]
		if !okFrom || !okTo {
			continue
		}

		relID := serializer.CanonicalID("relationship", fmt.Sprintf("rel-%d-%s-%s", i, rel.From, rel.To))
		spdxRel := &Relationship{
			BaseElement: BaseElement{
				Type:         "Relationship",
				SpdxID:       relID,
				CreationInfo: creationInfo,
			},
			From:             fromSpdx,
			To:               []string{toSpdx},
			RelationshipType: mapRelationshipType(rel.Type),
			Completeness:     "known",
		}
		elements = append(elements, spdxRel)
	}

	doc := &Document{
		Context: ContextIRI,
		Graph:   elements,
	}

	return serializer.Serialize(out, doc)
}

func mapKindToPrimaryPurpose(kind airom.ComponentKind) string {
	switch kind {
	case airom.KindHostedLLM, airom.KindLocalModelFile, airom.KindEmbeddingModel:
		return "machineLearningModel"
	case airom.KindFramework, airom.KindLibrary:
		return "framework"
	case airom.KindDataset:
		return "data"
	case airom.KindVectorDB:
		return "container"
	default:
		return "other"
	}
}

func mapRelationshipType(relType airom.RelType) RelationshipType {
	switch relType {
	case airom.RelDependsOn:
		return RelDependsOn
	case airom.RelTrainedOn:
		return RelTrainedOn
	case airom.RelConfigures:
		return RelConfiguredBy
	case airom.RelUses:
		return RelDelegatesTo
	case airom.RelDerivedFrom:
		return RelDerivedFrom
	case airom.RelContains:
		return RelContains
	default:
		return RelOther
	}
}
