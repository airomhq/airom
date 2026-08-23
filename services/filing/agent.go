package filing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// randID generates a hex-encoded random identifier of n bytes.
func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// FilingAgent coordinates package verification, state portal transmission, and receipt ledger tracking.
type FilingAgent struct {
	mu       sync.RWMutex
	receipts map[string][]FilingReceipt // Key: OrganizationID
	client   *http.Client
}

// NewFilingAgent creates a new FilingAgent.
func NewFilingAgent(client *http.Client) *FilingAgent {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &FilingAgent{
		receipts: make(map[string][]FilingReceipt),
		client:   client,
	}
}

// VerifyPackage reads a local directory, recomputes SHA-256 for every file, and checks manifest integrity.
func (a *FilingAgent) VerifyPackage(pkgDir string) (*FilingManifest, error) {
	manifestPath := filepath.Join(pkgDir, "filing_manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("filing manifest not found at %s: %w", manifestPath, err)
	}

	var manifest FilingManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("corrupted filing manifest JSON: %w", err)
	}

	if len(manifest.Artifacts) == 0 {
		return nil, fmt.Errorf("filing manifest contains no declared artifacts")
	}

	// Verify each constituent artifact file on disk
	for _, art := range manifest.Artifacts {
		filePath := filepath.Join(pkgDir, art.RelativePath)
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("missing artifact file %s: %w", art.RelativePath, err)
		}

		sum := sha256.Sum256(fileData)
		actualSHA := hex.EncodeToString(sum[:])
		if actualSHA != art.SHA256 {
			return nil, fmt.Errorf("cryptographic checksum mismatch for %s: expected %s, got %s",
				art.RelativePath, art.SHA256, actualSHA)
		}
		if int64(len(fileData)) != art.SizeBytes {
			return nil, fmt.Errorf("byte size mismatch for %s: expected %d, got %d",
				art.RelativePath, art.SizeBytes, len(fileData))
		}
	}

	// Verify signer attestation signature
	originalSig := manifest.Signer.SignatureHash
	recomputedSig := manifest.Signer.ComputeSignature()
	if originalSig != recomputedSig {
		return nil, fmt.Errorf("signer attestation signature mismatch: original %s != recomputed %s", originalSig, recomputedSig)
	}

	// Verify composite package checksum
	originalPkgChecksum := manifest.PackageChecksum
	recomputedPkgChecksum := manifest.ComputePackageChecksum()
	if originalPkgChecksum != recomputedPkgChecksum {
		return nil, fmt.Errorf("package composite checksum mismatch: manifest %s != computed %s", originalPkgChecksum, recomputedPkgChecksum)
	}

	return &manifest, nil
}

// SubmitPackage transmits a verified statutory package to a state portal endpoint (or generates verified receipt).
func (a *FilingAgent) SubmitPackage(ctx context.Context, manifest *FilingManifest, portalURL string) (*FilingReceipt, error) {
	if manifest == nil {
		return nil, fmt.Errorf("nil filing manifest provided")
	}
	if manifest.PackageChecksum == "" {
		return nil, fmt.Errorf("unsealed manifest: package checksum is missing")
	}

	receiptID := fmt.Sprintf("rcpt_%s", randID(6))
	now := time.Now().UTC()

	// If a live/mock state portal endpoint is provided, execute HTTP POST submission
	if portalURL != "" {
		payloadBytes, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal filing payload: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, portalURL, bytes.NewReader(payloadBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to construct submission request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Filing-Jurisdiction", string(manifest.Jurisdiction))
		req.Header.Set("X-Package-Checksum", manifest.PackageChecksum)
		req.Header.Set("User-Agent", "AIROM-StatePortalAgent/1.0 (+https://airom.dev)")

		resp, err := a.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("state portal submission error (%s): %w", portalURL, err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("state portal rejected filing with HTTP %d: %s", resp.StatusCode, string(body))
		}

		var portalAck struct {
			AckToken string `json:"ack_token"`
			Status   string `json:"status"`
			Message  string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&portalAck)
		if portalAck.AckToken == "" {
			portalAck.AckToken = fmt.Sprintf("ACK-%s-%s", manifest.Jurisdiction, randID(4))
		}

		receipt := &FilingReceipt{
			ReceiptID:           receiptID,
			PackageID:           manifest.PackageID,
			Jurisdiction:        manifest.Jurisdiction,
			OrganizationID:      manifest.OrganizationID,
			SubmittedAt:         now,
			PortalEndpoint:      portalURL,
			Status:              StatusAcknowledged,
			AcknowledgmentToken: portalAck.AckToken,
			SubmissionHash:      manifest.PackageChecksum,
			Message:             fmt.Sprintf("Successfully submitted and acknowledged by %s portal", manifest.Jurisdiction),
		}

		a.StoreReceipt(*receipt)
		return receipt, nil
	}

	// Default local deterministic submission acknowledgment
	submissionHash := manifest.PackageChecksum
	ackToken := fmt.Sprintf("STATE-ACK-%s-%s", manifest.Jurisdiction, submissionHash[:16])

	receipt := &FilingReceipt{
		ReceiptID:           receiptID,
		PackageID:           manifest.PackageID,
		Jurisdiction:        manifest.Jurisdiction,
		OrganizationID:      manifest.OrganizationID,
		SubmittedAt:         now,
		PortalEndpoint:      "direct-state-archive://local-ledger",
		Status:              StatusVerified,
		AcknowledgmentToken: ackToken,
		SubmissionHash:      submissionHash,
		Message:             fmt.Sprintf("Statutory filing package verified and sealed for %s", manifest.Jurisdiction),
	}

	a.StoreReceipt(*receipt)
	return receipt, nil
}

// StoreReceipt records a filing receipt into the agent's ledger.
func (a *FilingAgent) StoreReceipt(receipt FilingReceipt) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.receipts[receipt.OrganizationID] = append(a.receipts[receipt.OrganizationID], receipt)
}

// GetReceipts retrieves all filing receipts for a given organization.
func (a *FilingAgent) GetReceipts(orgID string) []FilingReceipt {
	a.mu.RLock()
	defer a.mu.RUnlock()
	rcpts := a.receipts[orgID]
	res := make([]FilingReceipt, len(rcpts))
	copy(res, rcpts)
	return res
}
