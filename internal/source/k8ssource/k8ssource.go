// Package k8ssource implements the Kubernetes Source (ARCHITECTURE.md §7) in
// OFFLINE MANIFEST MODE: it walks a directory of Kubernetes manifests
// (rendered YAML or Helm output), extracts the container images referenced by
// workload specs, dedupes them, and exposes them via Images(). The app fans
// each unique image out to the image source; this source's own Walk yields no
// entries — Images() (and Details()) is the primary API.
//
// AI-signal environment variables (OLLAMA_HOST, MODEL_ID, HF_TOKEN) observed on
// a container are attached to that container's image in Details().
//
// # Deviation
//
// LIVE CLUSTER MODE is intentionally not implemented: it requires client-go,
// which is not wired into this module. New returns a clear error when no
// ManifestsDir is set, directing the user to --manifests <dir>.
package k8ssource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Roro1727/airom/internal/classify"
	"github.com/Roro1727/airom/internal/source"
)

// aiSignalEnv are the environment variable names treated as AI signals.
var aiSignalEnv = map[string]bool{
	"OLLAMA_HOST": true,
	"MODEL_ID":    true,
	"HF_TOKEN":    true,
}

// recognizedKinds are the workload kinds we extract images from.
var recognizedKinds = map[string]bool{
	"Pod":         true,
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"ReplicaSet":  true,
	"Job":         true,
	"CronJob":     true,
}

// Options configures a k8s source.
type Options struct {
	// ManifestsDir enables offline manifest mode; when empty, New errors
	// (live-cluster mode is unimplemented).
	ManifestsDir string
}

// Image is a unique container image discovered across the manifests, plus any
// AI-signal env vars observed on containers that use it.
type Image struct {
	Ref       string            // the container image reference
	Workloads []string          // "Kind/namespace/name" locations it appears in
	Signals   map[string]string // AI-signal env vars (OLLAMA_HOST, MODEL_ID, HF_TOKEN)
}

// Source is the offline k8s implementation of source.Source.
type Source struct {
	dir string

	images   []Image // deduped, sorted by Ref
	byRef    map[string]*Image
	unknowns []source.Unknown
}

var _ source.Source = (*Source)(nil)

// New prepares an offline k8s manifest source. It requires opts.ManifestsDir;
// otherwise it reports that live-cluster scanning is unavailable.
func New(opts Options) (*Source, error) {
	if opts.ManifestsDir == "" {
		return nil, errors.New("live-cluster scanning requires client-go (deferred to a follow-up); use --manifests <dir> for offline manifest scanning")
	}
	abs, err := filepath.Abs(opts.ManifestsDir)
	if err != nil {
		return nil, fmt.Errorf("k8s source: resolve %q: %w", opts.ManifestsDir, err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("k8s source: cannot read manifests dir %q: %w", opts.ManifestsDir, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("k8s source: %q is not a directory", opts.ManifestsDir)
	}
	s := &Source{dir: abs, byRef: map[string]*Image{}}
	s.parse()
	return s, nil
}

// parse walks the manifests dir, extracting and deduping images. Per-file and
// per-document failures degrade to Unknowns (invariant P6); only an unreadable
// root would have failed earlier in New.
func (s *Source) parse() {
	err := filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			s.unknowns = append(s.unknowns, source.Unknown{Path: s.rel(path), Stage: "walk", Reason: err.Error()})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !isYAML(d.Name()) {
			return nil
		}
		s.parseFile(path)
		return nil
	})
	if err != nil {
		s.unknowns = append(s.unknowns, source.Unknown{Path: s.rel(s.dir), Stage: "walk", Reason: err.Error()})
	}
	s.finalize()
}

func (s *Source) parseFile(path string) {
	f, err := os.Open(path) // #nosec G304 -- reads manifest YAML under the user-specified manifests dir
	if err != nil {
		s.unknowns = append(s.unknowns, source.Unknown{Path: s.rel(path), Stage: "open", Reason: err.Error()})
		return
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	for i := 0; ; i++ {
		var doc workload
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			s.unknowns = append(s.unknowns, source.Unknown{
				Path:   fmt.Sprintf("%s[doc %d]", s.rel(path), i),
				Stage:  "parse",
				Reason: err.Error(),
			})
			// A malformed document derails the rest of this file's stream.
			break
		}
		s.collect(doc)
	}
}

// collect records the images (and AI signals) from one workload document.
func (s *Source) collect(doc workload) {
	if !recognizedKinds[doc.Kind] {
		return
	}
	where := doc.Kind
	if n := doc.Metadata.Name; n != "" {
		if ns := doc.Metadata.Namespace; ns != "" {
			where = doc.Kind + "/" + ns + "/" + n
		} else {
			where = doc.Kind + "/" + n
		}
	}
	for _, c := range doc.containers() {
		if c.Image == "" {
			continue
		}
		img := s.byRef[c.Image]
		if img == nil {
			img = &Image{Ref: c.Image, Signals: map[string]string{}}
			s.byRef[c.Image] = img
		}
		if !contains(img.Workloads, where) {
			img.Workloads = append(img.Workloads, where)
		}
		for _, e := range c.Env {
			if aiSignalEnv[e.Name] && e.Value != "" {
				img.Signals[e.Name] = e.Value
			}
		}
	}
}

func (s *Source) finalize() {
	refs := make([]string, 0, len(s.byRef))
	for ref := range s.byRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	s.images = make([]Image, 0, len(refs))
	for _, ref := range refs {
		img := s.byRef[ref]
		sort.Strings(img.Workloads)
		s.images = append(s.images, *img)
	}
}

// Images returns the deduped, sorted list of container image references found
// across the manifests. This is the primary API: the app fans each out to the
// image source.
func (s *Source) Images() []string {
	out := make([]string, len(s.images))
	for i, img := range s.images {
		out[i] = img.Ref
	}
	return out
}

// Details returns the deduped images with their workload locations and any
// AI-signal env vars observed on containers using them.
func (s *Source) Details() []Image {
	out := make([]Image, len(s.images))
	for i, img := range s.images {
		cp := Image{Ref: img.Ref, Workloads: append([]string(nil), img.Workloads...), Signals: map[string]string{}}
		for k, v := range img.Signals {
			cp.Signals[k] = v
		}
		out[i] = cp
	}
	return out
}

// Name returns the manifests directory.
func (s *Source) Name() string { return s.dir }

// Kind reports the source kind ("k8s").
func (s *Source) Kind() source.Kind { return source.KindK8s }

// ID is the content identity for the manifest set.
func (s *Source) ID() string { return "k8s:manifests:" + s.dir }

// Info returns the provenance root for the scan output.
func (s *Source) Info() source.Info { return source.Info{Kind: source.KindK8s, Target: s.dir} }

// Walk yields no entries: the k8s source contributes images, not files. The
// app enumerates Images() and fans each out to the image source. Walk exists to
// satisfy the Source contract and returns after publishing nothing.
func (s *Source) Walk(ctx context.Context, _ source.WalkFunc) error {
	return ctx.Err()
}

// WalkUnknowns returns manifest parse/read failures recorded during New.
func (s *Source) WalkUnknowns() []source.Unknown {
	return append([]source.Unknown(nil), s.unknowns...)
}

// Resolver returns a no-op query API: this source exposes images, not files.
func (s *Source) Resolver() source.Resolver { return noopResolver{} }

// Close is a no-op: the source holds no open resources.
func (s *Source) Close() error { return nil }

func (s *Source) rel(path string) string {
	if r, err := filepath.Rel(s.dir, path); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(path)
}

func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// noopResolver satisfies source.Resolver with empty results.
type noopResolver struct{}

func (noopResolver) FilesByGlob(context.Context, ...string) ([]classify.FileRef, error) {
	return nil, nil
}

func (noopResolver) Open(path string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("k8s source exposes images, not files: %q", path)
}

func (noopResolver) Stat(path string) (classify.FileRef, error) {
	return classify.FileRef{}, fmt.Errorf("k8s source exposes images, not files: %q", path)
}

// ── Manifest shapes (only the fields used for image extraction) ─────────────

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type container struct {
	Name  string   `yaml:"name"`
	Image string   `yaml:"image"`
	Env   []envVar `yaml:"env"`
}

type podSpec struct {
	Containers          []container `yaml:"containers"`
	InitContainers      []container `yaml:"initContainers"`
	EphemeralContainers []container `yaml:"ephemeralContainers"`
}

type podTemplate struct {
	Spec podSpec `yaml:"spec"`
}

type workload struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		// Pod-level (Kind: Pod).
		podSpec `yaml:",inline"`
		// Controllers with a pod template.
		Template podTemplate `yaml:"template"`
		// CronJob nests a job template.
		JobTemplate struct {
			Spec struct {
				Template podTemplate `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
}

// containers gathers every container (regular, init, ephemeral) from all of the
// document's possible pod-spec locations.
func (w workload) containers() []container {
	var out []container
	add := func(ps podSpec) {
		out = append(out, ps.Containers...)
		out = append(out, ps.InitContainers...)
		out = append(out, ps.EphemeralContainers...)
	}
	add(w.Spec.podSpec)                        // Pod
	add(w.Spec.Template.Spec)                  // Deployment/StatefulSet/DaemonSet/Job/ReplicaSet
	add(w.Spec.JobTemplate.Spec.Template.Spec) // CronJob
	return out
}
