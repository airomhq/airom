package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/app"
)

var nameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// newDevCmd is the contributor scaffolding (plugin-guide.md): create a rule
// pack or a code detector skeleton with fixtures and a test.
func newDevCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "dev",
		GroupID: groupDev,
		Short:   "Contributor scaffolding for new rule packs and detectors",
	}
	cmd.AddCommand(newDevRulePackCmd(), newDevDetectorCmd())
	return cmd
}

func newDevRulePackCmd() *cobra.Command {
	var category string
	cmd := &cobra.Command{
		Use:   "new-rulepack <name>",
		Short: "Scaffold a rule pack (rules/<category>/<name>.yaml) plus fixtures",
		Args:  exactArgs(1, "exactly one <name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !nameRe.MatchString(name) {
				return &app.UsageError{Err: fmt.Errorf("pack name %q must match [a-z0-9-]+", name)}
			}
			if !ruleCategories[category] {
				return &app.UsageError{Err: fmt.Errorf("category %q must be one of: %s",
					category, strings.Join(ruleCategoryList(), "|"))}
			}
			dir := filepath.Join("rules", category)
			packPath := filepath.Join(dir, name+".yaml")
			fixtureDir := filepath.Join(dir, "testdata", name)
			if _, err := os.Stat(packPath); err == nil {
				return &app.UsageError{Err: fmt.Errorf("%s already exists", packPath)}
			}
			if err := os.MkdirAll(fixtureDir, 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(packPath, []byte(rulepackTemplate(name)), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(fixtureDir, "sample.py"), []byte(rulepackFixture(name)), 0o600); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "created %s\n", packPath)
			fmt.Fprintf(w, "created %s\n", filepath.Join(fixtureDir, "sample.py"))
			fmt.Fprintf(w, "\nEdit the rule, then: airom rules lint %s\n", packPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&category, "category", "models",
		"rule category dir: "+strings.Join(ruleCategoryList(), "|"))
	return cmd
}

// ruleCategories are the rule-pack category directories under rules/.
//
// The name arg was validated and this was not, so it reached
// filepath.Join("rules", category) unchecked: `--category ../../escaped` wrote
// the scaffold outside the tree, and a plain typo silently created a category
// dir that does not exist. The flag's help already promised a closed set — this
// is that set, and it feeds the help string so the two cannot drift.
var ruleCategories = map[string]bool{
	"models": true, "embeddings": true, "frameworks": true, "vectordb": true,
	"infra": true, "params": true, "prompts": true, "datasets": true,
}

// ruleCategoryList returns the categories in a stable, documented order.
func ruleCategoryList() []string {
	out := make([]string, 0, len(ruleCategories))
	for c := range ruleCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func newDevDetectorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "new-detector <name>",
		Short: "Scaffold a Go code detector (internal/detectors/<name>/) plus a contract test",
		Args:  exactArgs(1, "exactly one <name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !nameRe.MatchString(name) {
				return &app.UsageError{Err: fmt.Errorf("detector name %q must match [a-z0-9-]+", name)}
			}
			pkg := detectorPkgName(name)
			dir := filepath.Join("internal", "detectors", pkg)
			if _, err := os.Stat(dir); err == nil {
				return &app.UsageError{Err: fmt.Errorf("%s already exists", dir)}
			}
			if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
				return err
			}
			files := map[string]string{
				filepath.Join(dir, pkg+".go"):      detectorTemplate(pkg, name),
				filepath.Join(dir, pkg+"_test.go"): detectorTestTemplate(pkg, name),
			}
			for path, content := range files {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					return err
				}
			}
			w := cmd.OutOrStdout()
			for path := range files {
				fmt.Fprintf(w, "created %s\n", path)
			}
			fmt.Fprintf(w, "\nImplement DetectFile, add fixtures under %s/, then:\n", filepath.Join(dir, "testdata"))
			fmt.Fprintf(w, "  go test ./%s/ -update   # write goldens\n", filepath.ToSlash(dir))
			fmt.Fprintf(w, "  go generate ./internal/detectors/all   # register it\n")
			return nil
		},
	}
}

func detectorPkgName(name string) string {
	return regexp.MustCompile(`-`).ReplaceAllString(name, "")
}
