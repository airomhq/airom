package frozen

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/airomhq/airom/internal/detectors/manifest"
	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// Per-sighting confidence, by how the version was established. The identity is
// equally certain in all three cases — the module IS in the archive — so the
// spread reflects the version claim, not whether the package is there.
const (
	// confMetadata: a bundled dist-info METADATA named the version. Same
	// standing as reading that file on disk.
	confMetadata = airom.Confidence(0.97)
	// confVersionAttr: a PEP 440 string recovered from the module's own
	// __version__. Strong, but a heuristic over compiled bytes.
	confVersionAttr = airom.Confidence(0.9)
	// confModuleOnly: the package is present and its version is unknown.
	// Deliberately still reported — see the note in DetectFile.
	confModuleOnly = airom.Confidence(0.8)
)

// Executable magics. The cookie sits at EOF, far past the shared header sample,
// so selection keys on "is this an executable at all" and the cookie check
// happens over ReaderAt — one small seek per binary rather than a full read.
var execMagics = []detect.Magic{
	{Offset: 0, Bytes: []byte{0x7f, 'E', 'L', 'F'}},    // ELF
	{Offset: 0, Bytes: []byte{'M', 'Z'}},               // PE
	{Offset: 0, Bytes: []byte{0xcf, 0xfa, 0xed, 0xfe}}, // Mach-O 64 LE
	{Offset: 0, Bytes: []byte{0xce, 0xfa, 0xed, 0xfe}}, // Mach-O 32 LE
	{Offset: 0, Bytes: []byte{0xca, 0xfe, 0xba, 0xbe}}, // Mach-O universal
	{Offset: 0, Bytes: []byte{0xbe, 0xba, 0xfe, 0xca}}, // Mach-O universal, swapped
}

// PyInstaller reports the AI packages frozen into a onefile executable.
type PyInstaller struct{}

// NewPyInstaller constructs the frozen-binary detector.
func NewPyInstaller() *PyInstaller { return &PyInstaller{} }

// ID is the stable detector identity.
func (PyInstaller) ID() string { return "frozen/pyinstaller" }

// Version participates in cache keys; bump on any behavior change.
func (PyInstaller) Version() int { return 1 }

// Selector matches executables and reads nothing eagerly. MaxSize is
// deliberately unset: a frozen application is routinely hundreds of megabytes,
// and gating on size would exclude exactly the files this detector exists for.
func (PyInstaller) Selector() detect.Selector {
	return detect.Selector{
		Magic: execMagics,
		Need:  detect.NeedHeader,
	}
}

// DetectFile parses the frozen archive and reports the AI packages inside it.
func (d PyInstaller) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	ra, err := f.ReaderAt()
	if err != nil {
		// Image and tar sources are consume-once. A frozen binary cannot be
		// read out of one, and saying so as an Unknown beats reporting the
		// executable as containing no AI.
		if errors.Is(err, detect.ErrNotSeekable) {
			return nil, fmt.Errorf("frozen: %s needs random access, which this source cannot provide: %w", f.Path(), err)
		}
		return nil, err
	}
	defer func() { _ = ra.Close() }()

	arc, err := ReadArchive(ra, f.Ref().Size)
	if err != nil {
		// Not a frozen binary is the answer for essentially every executable on
		// a machine, and is not worth an Unknown.
		if errors.Is(err, errNotFrozen) {
			return nil, nil
		}
		return nil, err
	}

	pyz, pyzRaw, versions := d.index(arc)
	if pyz == nil {
		return nil, nil
	}

	var out []detect.Finding
	for _, top := range pyz.TopLevelPackages() {
		kind, provider, canonical, ok := manifest.LookupPyPI(top)
		if !ok {
			continue // bundled, but not AI — an AIBOM is not an SBOM
		}
		version, how, conf := d.resolveVersion(pyz, pyzRaw, top, versions)
		out = append(out, detect.Finding{
			Claim: detect.ComponentClaim{
				Kind:     kind,
				Name:     canonical,
				Version:  version,
				Provider: provider,
				Package:  &detect.PackageClaim{Ecosystem: "pypi"},
			},
			Occurrence: airom.Occurrence{
				// Whole-file: the evidence is the executable, and there is no
				// line to point at inside a compiled archive.
				Location:   airom.Location{Line: 0},
				Method:     airom.MethodBinary,
				Confidence: conf,
				Snippet: fmt.Sprintf("frozen in a PyInstaller archive (%d modules); version %s",
					len(pyz.Modules), how),
			},
		})
	}
	return out, nil
}

// index reads the PYZ directory and collects the versions of any dist-info
// METADATA that rode along in the archive.
func (d PyInstaller) index(arc *Archive) (*PYZ, []byte, map[string]string) {
	versions := map[string]string{}
	var (
		pyz    *PYZ
		pyzRaw []byte
	)
	for _, e := range arc.Entries {
		switch {
		case e.IsPYZ() && pyz == nil:
			raw, err := arc.Read(e)
			if err != nil {
				continue
			}
			if p, err := ParsePYZ(raw); err == nil {
				pyz, pyzRaw = p, raw
			}
		case e.IsData() && strings.HasSuffix(e.Name, "METADATA"), e.IsData() && strings.HasSuffix(e.Name, "PKG-INFO"):
			// A bundled distribution's own metadata: the strongest version
			// evidence a frozen binary can carry, and how litellm and agno are
			// versioned today.
			raw, err := arc.Read(e)
			if err != nil {
				continue
			}
			if name, ver := metadataNameVersion(raw); name != "" && ver != "" {
				versions[normalizeTop(name)] = ver
			}
		}
	}
	return pyz, pyzRaw, versions
}

// resolveVersion applies the priority order, and reports which rung answered so
// the evidence can say. An unversioned component is still emitted: the package
// demonstrably IS in the binary, and dropping it — the behavior this detector
// replaces — reports a bundled AI framework as absent.
func (d PyInstaller) resolveVersion(pyz *PYZ, pyzRaw []byte, top string, versions map[string]string) (version, how string, conf airom.Confidence) {
	if v, ok := versions[normalizeTop(top)]; ok {
		return v, "from a bundled dist-info METADATA", confMetadata
	}
	if v := d.versionFromModule(pyz, pyzRaw, top); v != "" {
		return v, "from the module's __version__", confVersionAttr
	}
	return "", "unknown: no bundled metadata and no readable __version__", confModuleOnly
}

// versionAttrModules are where a package's version literal usually lives,
// most specific first.
func versionAttrModules(top string) []string {
	return []string{top + ".__version__", top + ".version", top + "._version", top}
}

// pep440 matches a release string conservatively: at least two dotted numeric
// components, optional pre/post/dev suffix. Loose enough for real versions,
// tight enough not to match every float-looking literal in a module.
var pep440 = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)*([abc]|rc|\.post|\.dev)?[0-9]*$`)

// versionFromModule digs a version literal out of a compiled module.
//
// The module body is never unmarshaled — the frozen interpreter's version
// rarely matches this binary's, and marshal is not a format to point at
// untrusted bytes. Instead the decompressed .pyc is scanned for short
// PEP 440-shaped strings, which is how a package that ships no dist-info (like
// crawl4ai) can be versioned at all.
func (d PyInstaller) versionFromModule(pyz *PYZ, pyzRaw []byte, top string) string {
	for _, name := range versionAttrModules(top) {
		m, ok := pyz.Lookup(name)
		if !ok {
			continue
		}
		// The PYZ member sits inside the PYZ entry, which the archive already
		// inflated once; re-read it through the same bounded path.
		body, ok := pyzMemberBytes(pyzRaw, m)
		if !ok {
			continue
		}
		if v := scanVersionLiteral(body); v != "" {
			return v
		}
	}
	return ""
}

// scanVersionLiteral finds the first plausible release string in compiled
// bytes. A .pyc stores str constants as length-prefixed ASCII, so candidates
// are recovered by walking printable runs.
//
// "0.0.0" is skipped: several packages (agno among them) set it as a
// placeholder and resolve the real version from installed metadata at runtime,
// so reporting it would be worse than reporting nothing.
func scanVersionLiteral(b []byte) string {
	const maxRun = 32
	start := -1
	for i := 0; i <= len(b); i++ {
		c := byte('\x00')
		if i < len(b) {
			c = b[i]
		}
		isVer := c == '.' || (c >= '0' && c <= '9') ||
			c == 'a' || c == 'b' || c == 'c' || c == 'r' || c == 'p' || c == 'd' || c == 'e' || c == 'v' || c == 's' || c == 't' || c == 'o'
		if isVer && i < len(b) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if run := string(b[start:i]); len(run) <= maxRun && run != "0.0.0" && pep440.MatchString(run) {
				return run
			}
			start = -1
		}
	}
	return ""
}

// pyzMemberBytes returns one module's stored bytes from the inflated PYZ.
// Each member is individually zlib-compressed; a member that does not inflate
// is used as-is rather than discarded, since only a version literal is wanted
// and some builds store members plain.
func pyzMemberBytes(pyzRaw []byte, m PYZModule) ([]byte, bool) {
	if m.Offset < 0 || m.Length <= 0 || m.Offset+m.Length > int64(len(pyzRaw)) {
		return nil, false
	}
	return inflateMaybe(pyzRaw[m.Offset : m.Offset+m.Length]), true
}

// metadataNameVersion pulls Name and Version out of an RFC 822 metadata blob,
// stopping at the blank line that ends the headers.
func metadataNameVersion(b []byte) (name, version string) {
	for _, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" {
			break
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "name":
			if name == "" {
				name = strings.TrimSpace(v)
			}
		case "version":
			if version == "" {
				version = strings.TrimSpace(v)
			}
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version
}

// normalizeTop folds a distribution or module name to a comparable key.
func normalizeTop(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", "-", ".", "-").Replace(s)
	// A dist-info name and an import name differ by separator far more often
	// than by anything else ("firecrawl-py" vs "firecrawl"); the catalog does
	// the rest.
	return strings.TrimSuffix(strings.Trim(s, "-"), "-py")
}
