package dataset

import (
	"fmt"
	"strings"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

// Translator projects AIROM dataset components into SPDX 3.0.1 Dataset Profile elements.
type Translator struct {
	serializer *spdx3.Serializer
}

// NewTranslator constructs a Dataset Profile translator.
func NewTranslator(serializer *spdx3.Serializer) *Translator {
	return &Translator{serializer: serializer}
}

// TranslateDataset projects an airom.Component into an SPDX 3.0.1 Dataset element.
func (t *Translator) TranslateDataset(c *airom.Component, creationInfo *spdx3.CreationInfo) (*Dataset, []spdx3.Element) {
	if c == nil {
		return nil, nil
	}

	spdxID := t.serializer.CanonicalID(string(c.Kind), string(c.ID))

	providerStr := spdx3.NoAssertion
	if v, ok := c.Provider.Value(); ok && v != "" {
		providerStr = v
	}

	verStr := spdx3.NoAssertion
	if v, ok := c.Version.Value(); ok && v != "" {
		verStr = v
	}

	ds := &Dataset{
		Package: spdx3.Package{
			BaseElement: spdx3.BaseElement{
				Type:         TypeDataset,
				SpdxID:       spdxID,
				CreationInfo: creationInfo,
				Name:         c.Name,
				Summary:      fmt.Sprintf("%s (dataset by %s)", c.Name, providerStr),
			},
			PackageVersion:   verStr,
			DownloadLocation: spdx3.NoAssertion,
			PrimaryPurpose:   "data",
			SuppliedBy:       providerStr,
		},
		DatasetType: "curated",
	}

	if c.PURL != "" {
		ds.ExternalIdentifier = append(ds.ExternalIdentifier, spdx3.ExternalIdentifier{
			Type:                   "ExternalIdentifier",
			ExternalIdentifierType: "purl",
			Identifier:             c.PURL,
		})
	}

	for _, h := range c.Hashes {
		ds.VerifiedUsing = append(ds.VerifiedUsing, spdx3.IntegrityMethod{
			Type:      "Hash",
			Algorithm: strings.ToLower(h.Alg),
			HashValue: h.Hex,
		})
	}

	if len(c.Licenses) > 0 {
		var lics []string
		for _, l := range c.Licenses {
			if l.SPDXID != "" {
				lics = append(lics, l.SPDXID)
			} else if l.Name != "" {
				lics = append(lics, l.Name)
			}
		}
		if len(lics) > 0 {
			ds.DeclaredLicense = strings.Join(lics, " AND ")
			ds.ConcludedLicense = ds.DeclaredLicense
		}
	}

	if c.Data != nil {
		if format, ok := c.Data.Format.Value(); ok {
			ds.DataFormat = format
		}
		if size, ok := c.Data.SizeBytes.Value(); ok {
			ds.SizeBytes = size
		}
		if url, ok := c.Data.URL.Value(); ok {
			ds.DatasetURL = url
			ds.DownloadLocation = url
		}
	}

	return ds, nil
}
