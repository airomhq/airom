package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

const maxMCPFileSize = 2 << 20 // 2 MiB

// MCP detects Model Context Protocol (MCP) servers, clients, and SDK integrations.
type MCP struct{}

// NewMCP constructs the Model Context Protocol detector.
func NewMCP() *MCP { return &MCP{} }

// ID returns the stable SARIF rule ID for this detector.
func (*MCP) ID() string { return "mcp/server" }

// Version participates in cache invalidation.
func (*MCP) Version() int { return 1 }

// Selector routes MCP configuration files and source code files.
func (*MCP) Selector() detect.Selector {
	return detect.Selector{
		PathGlobs: []string{
			"**/claude_desktop_config.json",
			"**/mcp.json",
			"**/.cursor/mcp.json",
			"**/mcp_config.json",
			"**/*mcp*.json",
			"**/*.py",
			"**/*.ts",
			"**/*.js",
			"**/*.tsx",
			"**/*.jsx",
		},
		MaxSize: maxMCPFileSize,
		Need:    detect.NeedContent,
	}
}

// mcpConfig represents the standard MCP configuration file schema.
type mcpConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	Servers    map[string]mcpServerEntry `json:"servers"`
}

type mcpServerEntry struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	Transport string            `json:"transport"`
	URL       string            `json:"url"`
}

// DetectFile parses the routed file for MCP server configurations or SDK integrations.
func (m *MCP) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil || len(content) == 0 {
		return nil, err
	}

	ext := strings.ToLower(path.Ext(f.Path()))

	if ext == ".json" {
		return m.detectConfigFile(f, content)
	}

	return m.detectCodeFile(f, content, ext)
}

func (m *MCP) detectConfigFile(f *detect.File, content []byte) ([]detect.Finding, error) {
	var cfg mcpConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, nil // Not a valid JSON or not an MCP config
	}

	servers := cfg.MCPServers
	if len(servers) == 0 {
		servers = cfg.Servers
	}
	if len(servers) == 0 {
		return nil, nil
	}

	var findings []detect.Finding

	for serverName, s := range servers {
		transport := s.Transport
		if transport == "" {
			if s.URL != "" {
				if strings.HasPrefix(s.URL, "ws") {
					transport = "websocket"
				} else {
					transport = "sse"
				}
			} else {
				transport = "stdio"
			}
		}

		endpoint := s.URL
		if endpoint == "" {
			endpoint = s.Command + " " + strings.Join(s.Args, " ")
		}

		finding := detect.Finding{
			Claim: detect.ComponentClaim{
				Kind:     airom.KindInfra,
				Name:     "mcp-server/" + serverName,
				Provider: "model-context-protocol",
				Infra: &detect.InfraClaim{
					Endpoint:   strings.TrimSpace(endpoint),
					Deployment: transport,
				},
			},
			Occurrence: airom.Occurrence{
				Location: airom.Location{
					Path: f.Path(),
					Line: 1,
				},
				DetectorID: m.ID(),
				Method:     airom.MethodManifest,
				Confidence: 1.0,
				Snippet:    truncateSnippet(string(content), 180),
				Fields: map[string]string{
					"server_name": serverName,
					"transport":   transport,
					"command":     s.Command,
				},
			},
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (m *MCP) detectCodeFile(f *detect.File, content []byte, ext string) ([]detect.Finding, error) {
	lines := bytes.Split(content, []byte("\n"))
	var findings []detect.Finding

	for idx, lineBytes := range lines {
		lineStr := strings.TrimSpace(string(lineBytes))
		if lineStr == "" || strings.HasPrefix(lineStr, "#") || strings.HasPrefix(lineStr, "//") {
			continue
		}

		lineNum := idx + 1
		matchedSDK := ""
		ecosystem := ""

		switch ext {
		case ".py":
			if strings.Contains(lineStr, "import mcp") || strings.Contains(lineStr, "from mcp") || strings.Contains(lineStr, "FastMCP(") {
				matchedSDK = "mcp"
				ecosystem = "pypi"
			}
		case ".ts", ".js", ".tsx", ".jsx":
			if strings.Contains(lineStr, "@modelcontextprotocol/sdk") || strings.Contains(lineStr, "@modelcontextprotocol/server") {
				matchedSDK = "@modelcontextprotocol/sdk"
				ecosystem = "npm"
			}
		}

		if matchedSDK != "" {
			findings = append(findings, detect.Finding{
				Claim: detect.ComponentClaim{
					Kind:     airom.KindFramework,
					Name:     matchedSDK,
					Provider: "model-context-protocol",
					Package: &detect.PackageClaim{
						Ecosystem: ecosystem,
					},
				},
				Occurrence: airom.Occurrence{
					Location: airom.Location{
						Path: f.Path(),
						Line: lineNum,
					},
					DetectorID: m.ID(),
					Method:     airom.MethodConfig,
					Confidence: 0.8,
					Snippet:    truncateSnippet(lineStr, 150),
					Fields: map[string]string{
						"sdk":       matchedSDK,
						"ecosystem": ecosystem,
					},
				},
			})
			break // Emit 1 SDK finding per file
		}
	}

	return findings, nil
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
