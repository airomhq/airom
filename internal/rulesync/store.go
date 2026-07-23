package rulesync

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
)

// current.json is the pointer at <cache>/rules that names the active bundle.
// It is written last, after a successful extract, so a reader never sees it
// point at a half-installed version.
type current struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	FetchedAt string `json:"fetchedAt"`
}

func currentPath(cacheDir string) string { return filepath.Join(rulesDir(cacheDir), "current.json") }

func writeCurrent(cacheDir string, c current) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDir(cacheDir), 0o750); err != nil {
		return err
	}
	return os.WriteFile(currentPath(cacheDir), append(b, '\n'), 0o600)
}

// Active returns the currently installed rule bundle as a filesystem plus its
// version, or ok=false when no valid bundle is cached (so the caller falls back
// to the embedded packs). It never touches the network and never errors: a
// missing, unreadable, or dangling pointer is simply "no bundle", because a
// scan must degrade to the embedded floor, never fail on a bad cache.
func Active(cacheDir string) (bundle fs.FS, version string, ok bool) {
	b, err := os.ReadFile(currentPath(cacheDir))
	if err != nil {
		return nil, "", false
	}
	var c current
	if err := json.Unmarshal(b, &c); err != nil || c.Version == "" {
		return nil, "", false
	}
	dir := filepath.Join(rulesDir(cacheDir), c.Version)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, "", false
	}
	return os.DirFS(dir), c.Version, true
}
