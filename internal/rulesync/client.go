package rulesync

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Doer is the minimal HTTP surface Update needs, so tests can inject a
// server-free transport (mirrors internal/osv).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// maxAsset caps any single download. Rule bundles are kilobytes; this is a
// generous ceiling that still bounds memory against a hostile or wrong URL.
const maxAsset = 32 << 20 // 32 MiB

// get fetches one asset with a bounded read. A non-200 status is an error, so a
// GitHub "not found" HTML page never gets mistaken for a manifest or tarball.
func get(ctx context.Context, client Doer, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if len(b) > maxAsset {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxAsset)
	}
	return b, nil
}
