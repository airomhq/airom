package rulesync

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
)

// embeddedKey is the airom-rules signing public key baked into this build. The
// file carries a single base64-encoded 32-byte ed25519 key (comments with '#'
// are ignored). It is a placeholder until the airom-rules integration commits
// the real key; a build without a key can only fetch under InsecureSkipSignature.
//
//go:embed airom-rules.pub
var embeddedKey []byte

// embeddedPublicKey parses embeddedKey, returning nil when no key is present.
func embeddedPublicKey() ed25519.PublicKey {
	for _, line := range strings.Split(string(embeddedKey), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		return ed25519.PublicKey(raw)
	}
	return nil
}

// verifyManifest checks the detached ed25519 signature over the manifest bytes.
// sig is base64-encoded. It fails closed: an absent key, a malformed signature,
// or a bad signature all return an error. The caller decides whether to call it
// at all (InsecureSkipSignature bypasses both this and the signature fetch).
func verifyManifest(manifest, sig []byte, key ed25519.PublicKey) error {
	if key == nil {
		return ErrNoSigningKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return fmt.Errorf("%w: signature is not valid base64: %v", ErrSignature, err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrSignature, len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, manifest, raw) {
		return ErrSignature
	}
	return nil
}
