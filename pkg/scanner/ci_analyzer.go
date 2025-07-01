package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// CIAnalyzer scans for CI/CD and build configuration files
type CIAnalyzer struct{}

// NewCIAnalyzer creates a new CI/CD analyzer
func NewCIAnalyzer() *CIAnalyzer {
	return &CIAnalyzer{}
}

func (c *CIAnalyzer) Name() string {
	return "ci-analyzer"
}

func (c *CIAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeMakefile,
		artifact.TypeCMakeLists,
		artifact.TypeBuildScript,
		artifact.TypeJenkinsfile,
		artifact.TypeGitHubActions,
		artifact.TypeGitLabCI,
		artifact.TypeCircleCI,
		artifact.TypeTravisCI,
		artifact.TypeAzurePipelines,
		artifact.TypeBuildkite,
		artifact.TypeDroneCI,
	}
}

func (c *CIAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())
		filePath := strings.ToLower(path)
		relPath, _ := filepath.Rel(source.Location, path)

		var artifactType artifact.Type
		var metadata map[string]string

		switch {
		// Build systems
		case fileName == "makefile" || fileName == "gnumakefile" || strings.HasSuffix(fileName, ".mk"):
			artifactType = artifact.TypeMakefile
			metadata = map[string]string{
				"build_system": "make",
				"file_type":    "makefile",
			}

		case fileName == "cmakelists.txt":
			artifactType = artifact.TypeCMakeLists
			metadata = map[string]string{
				"build_system": "cmake",
				"file_type":    "cmake",
			}

		case fileName == "build.sh" || fileName == "build.bat" || fileName == "build.ps1":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "shell",
				"file_type":    c.getScriptType(fileName),
			}

		case strings.HasSuffix(fileName, ".gradle") || fileName == "gradlew" || fileName == "gradlew.bat":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "gradle",
				"file_type":    "gradle",
			}

		case fileName == "pom.xml":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "maven",
				"file_type":    "xml",
			}

		case fileName == "package.json" && c.hasScripts(path):
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "npm",
				"file_type":    "json",
			}

		// CI/CD Systems
		case fileName == "jenkinsfile" || strings.HasSuffix(fileName, ".jenkinsfile"):
			artifactType = artifact.TypeJenkinsfile
			metadata = map[string]string{
				"ci_system": "jenkins",
				"file_type": "jenkinsfile",
				"pipeline":  "true",
			}

		// GitHub Actions
		case strings.Contains(strings.ReplaceAll(filePath, "\\", "/"), ".github/workflows/") &&
			(strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml")):
			artifactType = artifact.TypeGitHubActions
			metadata = map[string]string{
				"ci_system": "github-actions",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// GitLab CI
		case fileName == ".gitlab-ci.yml" || fileName == ".gitlab-ci.yaml":
			artifactType = artifact.TypeGitLabCI
			metadata = map[string]string{
				"ci_system": "gitlab",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// CircleCI
		case strings.Contains(strings.ReplaceAll(filePath, "\\", "/"), ".circleci/") && fileName == "config.yml":
			artifactType = artifact.TypeCircleCI
			metadata = map[string]string{
				"ci_system": "circleci",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// Travis CI
		case fileName == ".travis.yml":
			artifactType = artifact.TypeTravisCI
			metadata = map[string]string{
				"ci_system": "travis",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// Azure Pipelines
		case fileName == "azure-pipelines.yml" || fileName == "azure-pipelines.yaml" ||
			fileName == ".azure-pipelines.yml" || fileName == ".azure-pipelines.yaml":
			artifactType = artifact.TypeAzurePipelines
			metadata = map[string]string{
				"ci_system": "azure-pipelines",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// Buildkite
		case strings.Contains(strings.ReplaceAll(filePath, "\\", "/"), ".buildkite/") && fileName == "pipeline.yml":
			artifactType = artifact.TypeBuildkite
			metadata = map[string]string{
				"ci_system": "buildkite",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// Drone CI
		case fileName == ".drone.yml":
			artifactType = artifact.TypeDroneCI
			metadata = map[string]string{
				"ci_system": "drone",
				"file_type": "yaml",
				"pipeline":  "true",
			}

		// Additional build files
		case fileName == "cargo.toml":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "cargo",
				"file_type":    "toml",
			}

		case fileName == "setup.py" || fileName == "setup.cfg" || fileName == "pyproject.toml":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "python",
				"file_type":    c.getPythonBuildType(fileName),
			}

		case fileName == "composer.json":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "composer",
				"file_type":    "json",
			}

		case fileName == "gemfile":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "bundler",
				"file_type":    "ruby",
			}

		case fileName == "mix.exs":
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "mix",
				"file_type":    "elixir",
			}

		case fileName == "dune-project" || strings.HasSuffix(fileName, ".opam"):
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": "dune",
				"file_type":    "ocaml",
			}

		case fileName == "stack.yaml" || strings.HasSuffix(fileName, ".cabal"):
			artifactType = artifact.TypeBuildScript
			metadata = map[string]string{
				"build_system": c.getHaskellBuildSystem(fileName),
				"file_type":    "haskell",
			}
		}

		if artifactType != "" {
			modTime := info.ModTime()
			artifact := artifact.Artifact{
				Name:        info.Name(),
				Type:        artifactType,
				Path:        relPath,
				Source:      source,
				Size:        info.Size(),
				Permissions: info.Mode().String(),
				ModTime:     &modTime,
				Metadata:    metadata,
			}
			artifacts = append(artifacts, artifact)
		}

		return nil
	})

	return artifacts, err
}

func (c *CIAnalyzer) getScriptType(fileName string) string {
	switch {
	case strings.HasSuffix(fileName, ".sh"):
		return "shell"
	case strings.HasSuffix(fileName, ".bat"):
		return "batch"
	case strings.HasSuffix(fileName, ".ps1"):
		return "powershell"
	default:
		return "script"
	}
}

func (c *CIAnalyzer) hasScripts(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Check if package.json has scripts section
	return strings.Contains(contentStr, "\"scripts\":")
}

func (c *CIAnalyzer) getPythonBuildType(fileName string) string {
	switch fileName {
	case "setup.py":
		return "setuptools"
	case "setup.cfg":
		return "setuptools-cfg"
	case "pyproject.toml":
		return "pyproject"
	default:
		return "python"
	}
}

func (c *CIAnalyzer) getHaskellBuildSystem(fileName string) string {
	switch {
	case fileName == "stack.yaml":
		return "stack"
	case strings.HasSuffix(fileName, ".cabal"):
		return "cabal"
	default:
		return "haskell"
	}
}
