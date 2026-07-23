package rulesync

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"
)

// Sentinel errors — callers match with errors.Is to map to exit codes and
// messages. Every one is fail-closed: on any of them, the cache is left
// untouched and the previously active bundle (or the embedded packs) stands.
var (
	// ErrOffline is returned before any network call when Offline is set.
	ErrOffline = errors.New("rulesync: offline — refusing to fetch a rule bundle over the network")
	// ErrNoSigningKey means this airom build embeds no rules-signing public key
	// (verification impossible). Bypass with InsecureSkipSignature at your risk.
	ErrNoSigningKey = errors.New("rulesync: this airom build has no rules-signing public key embedded")
	// ErrSignature means the manifest's ed25519 signature did not verify.
	ErrSignature = errors.New("rulesync: bundle signature verification failed")
	// ErrIntegrity means the downloaded tarball's SHA-256 did not match the
	// (signed) manifest — corruption or tampering after signing.
	ErrIntegrity = errors.New("rulesync: bundle checksum mismatch")
	// ErrVersionMismatch means a pinned version was requested but the fetched
	// manifest declared a different one.
	ErrVersionMismatch = errors.New("rulesync: fetched bundle version does not match the requested version")
)

// Options configures a single Update. Zero values pick safe defaults.
type Options struct {
	CacheDir string // where bundles live; the caller resolves the default
	Version  string // "" or "latest" → the newest release; otherwise pinned (e.g. "v1.2.0")
	Source   string // base URL override (mirror/testing); "" → the GitHub release channel

	Offline               bool // refuse to touch the network (fail before dialing)
	InsecureSkipSignature bool // skip ed25519 verification — integrity check still runs

	HTTP      Doer              // nil → a default 30s http.Client
	PublicKey ed25519.PublicKey // nil → the key embedded in this build (tests inject their own)
	Now       func() time.Time  // nil → time.Now; injectable for deterministic tests
}

// Manifest is the signed description of a bundle. The ed25519 signature covers
// the exact bytes of the manifest.json that carries these fields.
type Manifest struct {
	Version   string `json:"version"`   // e.g. "v1.2.0"
	Tarball   string `json:"tarball"`   // asset filename of the gzipped tar
	SHA256    string `json:"sha256"`    // lowercase hex of the tarball
	RuleCount int    `json:"ruleCount"` // informational
	PackCount int    `json:"packCount"` // informational
}

// Result reports what Update installed.
type Result struct {
	Version   string // the manifest version now active
	SHA256    string // the tarball hash
	Path      string // the extracted bundle directory
	RuleCount int
	PackCount int
}

// Update fetches, verifies, and installs a rule bundle into the cache, then
// repoints current.json at it. It is the ONLY function here that touches the
// network. On any error the cache is left as it was.
func Update(ctx context.Context, o Options) (*Result, error) {
	if o.Offline {
		return nil, ErrOffline
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	base := resolveBase(o.Source, o.Version)

	// 1. manifest + detached signature.
	manifestBytes, err := get(ctx, client, base+"/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	// 2. authenticity — verify BEFORE trusting any field in the manifest. The
	// signature (and its fetch) is skipped only under an explicit opt-out; the
	// integrity check below still runs.
	if !o.InsecureSkipSignature {
		sigBytes, err := get(ctx, client, base+"/manifest.json.sig")
		if err != nil {
			return nil, fmt.Errorf("fetch signature: %w", err)
		}
		key := o.PublicKey
		if key == nil {
			key = embeddedPublicKey() // the key baked into this build
		}
		if err := verifyManifest(manifestBytes, sigBytes, key); err != nil {
			return nil, err
		}
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version == "" || m.Tarball == "" || m.SHA256 == "" {
		return nil, fmt.Errorf("manifest is missing version, tarball, or sha256")
	}
	if o.Version != "" && o.Version != "latest" && m.Version != o.Version {
		return nil, fmt.Errorf("%w: requested %q, got %q", ErrVersionMismatch, o.Version, m.Version)
	}

	// 3. the tarball + integrity check against the signed manifest.
	tarball, err := get(ctx, client, base+"/"+m.Tarball)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	if sum := hex.EncodeToString(sha256Sum(tarball)); sum != m.SHA256 {
		return nil, fmt.Errorf("%w: manifest %s, got %s", ErrIntegrity, m.SHA256, sum)
	}

	// 4. extract into the cache, atomically, and repoint current.json.
	dir, err := install(o.CacheDir, m.Version, tarball)
	if err != nil {
		return nil, err
	}
	if err := writeCurrent(o.CacheDir, current{Version: m.Version, SHA256: m.SHA256, FetchedAt: now().UTC().Format(time.RFC3339)}); err != nil {
		return nil, err
	}
	return &Result{Version: m.Version, SHA256: m.SHA256, Path: dir, RuleCount: m.RuleCount, PackCount: m.PackCount}, nil
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// rulesDir is the per-cache root that holds one subdir per installed version
// plus current.json. Callers pass the resolved airom cache dir.
func rulesDir(cacheDir string) string { return filepath.Join(cacheDir, "rules") }

// The default release channel. Version selects the latest vs a pinned release;
// both expose the assets at a flat <base>/<asset> path (GitHub's
// releases/{latest/download,download/<tag>} layout).
const defaultRepo = "https://github.com/airomhq/airom-rules"

func resolveBase(source, version string) string {
	if source != "" {
		return trimSlash(source)
	}
	if version == "" || version == "latest" {
		return defaultRepo + "/releases/latest/download"
	}
	return defaultRepo + "/releases/download/" + version
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
