package manifest

import (
	"context"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// FuzzManifestDetectors asserts the contract every manifest parser must hold:
// arbitrary untrusted bytes yield findings or an error, never a panic
// (ARCHITECTURE.md §13). It exercises all eight detectors on each input.
func FuzzManifestDetectors(f *testing.F) {
	seeds := [][]byte{
		[]byte("openai==1.30.0\nrequests>=2.0\n"),
		[]byte("[project]\ndependencies = [\n  \"openai>=1.0\",\n]\n"),
		[]byte("[tool.poetry.dependencies]\npython = \"^3.10\"\nopenai = \"^1.0\"\n"),
		[]byte(`{"dependencies":{"openai":"^4.0.0","express":"^4"}}`),
		[]byte("module m\n\ngo 1.23\n\nrequire github.com/ollama/ollama v0.2.1\n"),
		[]byte(`<project><dependencies><dependency><groupId>io.milvus</groupId><artifactId>milvus-sdk-java</artifactId><version>2.4.1</version></dependency></dependencies></project>`),
		[]byte("dependencies {\n  implementation 'dev.langchain4j:langchain4j:0.35.0'\n}\n"),
		[]byte("[dependencies]\nasync-openai = \"0.23\"\ntokio = { version = \"1\" }\n"),
		[]byte(`<Project><ItemGroup><PackageReference Include="OpenAI" Version="1.0.0" /></ItemGroup></Project>`),
		[]byte(""),
		[]byte("{"),
		[]byte("<"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	dets := []detect.FileDetector{
		NewRequirements(), NewPyProject(), NewPackageJSON(), NewGoMod(),
		NewMaven(), NewGradle(), NewCargo(), NewCSProj(),
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, d := range dets {
			header := data
			if len(header) > 32*1024 {
				header = header[:32*1024]
			}
			file := detect.NewFile(
				detect.FileRef{Path: "fuzz.input", Size: int64(len(data))},
				header,
				detect.FileProviders{
					Content: func() ([]byte, bool, error) { return data, false, nil },
				},
			)
			// The result is irrelevant; the requirement is "no panic".
			_, _ = d.DetectFile(context.Background(), file)
		}
	})
}
