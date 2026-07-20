// Package gitsource implements the remote-repository Source (ARCHITECTURE.md
// §7): git clone --depth=1 --single-branch --no-tags via an exec-git fast
// path when a git binary is available, with a go-git v6 fallback (decision
// D14: go-git's shallow-clone inefficiency is documented; established scanners
// shell out too). After acquisition it delegates the scan entirely to dirsource.
//
// Local repository paths scan directly as plain filesystems; git metadata
// (remote, commit, dirty state) feeds SourceInfo provenance either way, so
// the inventory records exactly what revision was scanned.
package gitsource
