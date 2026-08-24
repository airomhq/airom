package bundle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrCorruptedArchive is returned when an air-gap package fails cryptographic verification.
var ErrCorruptedArchive = errors.New("air-gap bundle verification failed: hash mismatch or invalid signature")

// Compiler builds and verifies sealed offline air-gap archives.
type Compiler struct {
	signingKey []byte
}

// NewCompiler constructs an air-gap bundle compiler.
func NewCompiler(signingKey []byte) *Compiler {
	if len(signingKey) == 0 {
		signingKey = []byte("airom-sovereign-default-signing-key-2026")
	}
	return &Compiler{signingKey: signingKey}
}

// BuildBundle packages rules, WASM parsers, and vulnerability databases into a certified bundle.
func (c *Compiler) BuildBundle(bundleID, version string, payloads map[string][]byte, numRules, numWasm, numVulns int) AirGapPackage {
	// 1. Deterministic Content Hashing
	var paths []string
	for p := range payloads {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write(payloads[p])
	}
	contentHash := hex.EncodeToString(h.Sum(nil))

	// 2. Cryptographic Signature (Cosign / HMAC-SHA256)
	mac := hmac.New(sha256.New, c.signingKey)
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s", bundleID, version, contentHash)))
	sig := hex.EncodeToString(mac.Sum(nil))

	manifest := Manifest{
		BundleID:        bundleID,
		Version:         version,
		CompiledAt:      time.Now().UTC(),
		RulePackCount:   numRules,
		WasmParserCount: numWasm,
		VulnDBEntries:   numVulns,
		ContentSHA256:   contentHash,
		CosignSignature: sig,
		AirGapCertified: true,
	}

	return AirGapPackage{
		Manifest: manifest,
		Payloads: payloads,
	}
}

// VerifyBundle checks the cryptographic integrity and signature of an offline package.
func (c *Compiler) VerifyBundle(pkg AirGapPackage) error {
	var paths []string
	for p := range pkg.Payloads {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write(pkg.Payloads[p])
	}
	computedHash := hex.EncodeToString(h.Sum(nil))

	if computedHash != pkg.Manifest.ContentSHA256 {
		return fmt.Errorf("%w: content hash mismatch (%s vs %s)", ErrCorruptedArchive, computedHash, pkg.Manifest.ContentSHA256)
	}

	mac := hmac.New(sha256.New, c.signingKey)
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s", pkg.Manifest.BundleID, pkg.Manifest.Version, computedHash)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if expectedSig != pkg.Manifest.CosignSignature {
		return fmt.Errorf("%w: invalid cryptographic signature", ErrCorruptedArchive)
	}

	return nil
}
