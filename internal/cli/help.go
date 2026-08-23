package cli

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/tui"
)

// Command groups. Cobra renders ungrouped commands under "Additional Commands",
// so every command we own declares a GroupID; the leftovers are cobra's own
// (help, completion), which is exactly where they belong.
const (
	groupScan       = "scan"
	groupInspect    = "inspect"
	groupDev        = "dev"
	groupCompliance = "compliance"
)

// helpPalette styles help text. Help goes to stdout, so that is what we probe:
// piped into `less` or a file it degrades to plain text automatically.
var helpPalette = tui.NewPalette(os.Stdout)

// installHelp gives the command tree grouped, styled help.
//
// Cobra's default is one flat list of every command and one undifferentiated
// wall of flags — fine at four commands, unreadable at twelve. Grouping answers
// "what can this thing do?" at a glance, and the styling is a no-op the moment
// output is not a terminal.
func installHelp(root *cobra.Command) {
	// Preserve registration order instead of sorting alphabetically: `scan` is
	// the command most people want and should lead its group, not trail it
	// because "s" > "fs". The AddCommand order in newRootCmd is the intended
	// reading order.
	cobra.EnableCommandSorting = false

	root.AddGroup(
		&cobra.Group{ID: groupScan, Title: heading("Scan a target:")},
		&cobra.Group{ID: groupInspect, Title: heading("Inspect what AIROM knows:")},
		&cobra.Group{ID: groupDev, Title: heading("Author detectors:")},
		&cobra.Group{ID: groupCompliance, Title: heading("Compliance, Filings & Renewals:")},
	)

	cobra.AddTemplateFunc("hd", heading)
	cobra.AddTemplateFunc("accent", helpPalette.Accent.S)
	cobra.AddTemplateFunc("dim", helpPalette.Dim.S)

	root.SetUsageTemplate(usageTemplate)
	root.SetHelpTemplate(helpTemplate)
}

func heading(s string) string { return helpPalette.Heading.S(s) }

// helpTemplate is the whole-page layout: the description, then the usage block.
const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

// usageTemplate mirrors cobra's default structure with grouping, color, and
// breathing room. Kept close to the original so cobra upgrades stay boring.
const usageTemplate = `{{hd "Usage:"}}{{if .Runnable}}
  {{accent .UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{accent .CommandPath}} {{accent "[command]"}}{{end}}{{if gt (len .Aliases) 0}}

{{hd "Aliases:"}}
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{hd "Examples:"}}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{hd "Available Commands:"}}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding | accent}} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding | accent}} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{hd "Additional Commands:"}}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding | accent}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{hd "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

{{hd "Global flags:"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

{{hd "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding | accent}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

{{dim "Use"}} {{accent (printf "%s [command] --help" .CommandPath)}} {{dim "for more information about a command."}}{{end}}
`

// indent left-pads each line of an example block.
func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		b.WriteString("  " + line + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// example renders an annotated example block: dim comments, accented commands.
func example(pairs ...[2]string) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('\n')
		}
		if p[0] != "" {
			b.WriteString(helpPalette.Dim.S("# "+p[0]) + "\n")
		}
		b.WriteString(p[1] + "\n")
	}
	return indent(b.String())
}
