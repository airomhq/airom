package mcp

import (
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

func newMockFile(filePath string, content []byte) *detect.File {
	return detect.NewFile(
		detect.FileRef{Path: filePath},
		content,
		detect.FileProviders{
			Content: func() ([]byte, bool, error) {
				return content, false, nil
			},
		},
	)
}

func TestMCP_DetectConfigFile_Success(t *testing.T) {
	configJSON := `{
  "mcpServers": {
    "sqlite": {
      "command": "uvx",
      "args": ["mcp-server-sqlite", "--db-path", "/data/app.db"]
    },
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    },
    "weather": {
      "url": "http://localhost:8000/sse",
      "transport": "sse"
    }
  }
}`

	detector := NewMCP()
	f := newMockFile("claude_desktop_config.json", []byte(configJSON))

	findings, err := detector.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile failed: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	foundServers := make(map[string]bool)
	for _, finding := range findings {
		foundServers[finding.Claim.Name] = true
		if finding.Claim.Kind != airom.KindInfra {
			t.Errorf("expected KindInfra, got %s", finding.Claim.Kind)
		}
		if finding.Occurrence.Confidence != 1.0 {
			t.Errorf("expected Confidence 1.0, got %v", finding.Occurrence.Confidence)
		}
	}

	for _, want := range []string{"mcp-server/sqlite", "mcp-server/fetch", "mcp-server/weather"} {
		if !foundServers[want] {
			t.Errorf("missing expected server %q in findings: %+v", want, foundServers)
		}
	}
}

func TestMCP_DetectPythonSDK_Success(t *testing.T) {
	pyCode := `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("WeatherService")

@mcp.tool()
def get_temperature(city: str) -> float:
    return 72.5
`

	detector := NewMCP()
	f := newMockFile("src/agent/weather_mcp.py", []byte(pyCode))

	findings, err := detector.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Claim.Name != "mcp" {
		t.Errorf("expected SDK name 'mcp', got %s", finding.Claim.Name)
	}
	if finding.Claim.Package.Ecosystem != "pypi" {
		t.Errorf("expected ecosystem 'pypi', got %s", finding.Claim.Package.Ecosystem)
	}
	if finding.Occurrence.Location.Line != 1 {
		t.Errorf("expected line 1, got %d", finding.Occurrence.Location.Line)
	}
}

func TestMCP_DetectTypeScriptSDK_Success(t *testing.T) {
	tsCode := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({
  name: "demo-server",
  version: "1.0.0"
});
`

	detector := NewMCP()
	f := newMockFile("src/mcp_server.ts", []byte(tsCode))

	findings, err := detector.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatalf("DetectFile failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Claim.Name != "@modelcontextprotocol/sdk" {
		t.Errorf("expected SDK name '@modelcontextprotocol/sdk', got %s", finding.Claim.Name)
	}
	if finding.Claim.Package.Ecosystem != "npm" {
		t.Errorf("expected ecosystem 'npm', got %s", finding.Claim.Package.Ecosystem)
	}
}
