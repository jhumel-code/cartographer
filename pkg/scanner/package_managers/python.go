package package_managers

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
)

const (
	RequirementsTxtFile = "requirements.txt"
	PipfileLockFile     = "Pipfile.lock"
	SetupPyFile         = "setup.py"
	PyprojectTomlFile   = "pyproject.toml"
	PoetryLockFile      = "poetry.lock"
	CondaYamlFile       = "environment.yml"
)

// PythonScanner scans for Python package dependencies
type PythonScanner struct {
	*core.BaseScanner
}

// NewPythonScanner creates a new Python scanner
func NewPythonScanner() *PythonScanner {
	patterns := []string{
		RequirementsTxtFile,
		PipfileLockFile,
		SetupPyFile,
		PyprojectTomlFile,
		PoetryLockFile,
		CondaYamlFile,
		"requirements-*.txt",
		"*requirements.txt",
	}

	supportedTypes := []artifact.Type{
		artifact.TypePythonPackage,
		artifact.TypeCondaPackage,
	}

	return &PythonScanner{
		BaseScanner: core.NewBaseScanner("python-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Python packages in the source
func (p *PythonScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return p.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !p.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case RequirementsTxtFile:
			return p.parseRequirementsTxt(path, source)
		case PipfileLockFile:
			return p.parsePipfileLock(path, source)
		case SetupPyFile:
			return p.parseSetupPy(path, source)
		case PyprojectTomlFile:
			return p.parsePyprojectToml(path, source)
		case PoetryLockFile:
			return p.parsePoetryLock(path, source)
		case CondaYamlFile:
			return p.parseCondaEnvironment(path, source)
		default:
			// Handle requirements-*.txt patterns
			if strings.HasPrefix(filename, "requirements") && strings.HasSuffix(filename, ".txt") {
				return p.parseRequirementsTxt(path, source)
			}
		}

		return nil, nil
	})
}

// parseRequirementsTxt parses a requirements.txt file
func (p *PythonScanner) parseRequirementsTxt(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([<>=!~]+.*)?\s*(?:#.*)?$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip flags and includes
		if strings.HasPrefix(line, "-") {
			continue
		}

		matches := packageRegex.FindStringSubmatch(line)
		if matches != nil {
			name := matches[1]
			versionSpec := ""
			if len(matches) > 2 && matches[2] != "" {
				versionSpec = strings.TrimSpace(matches[2])
			}

			metadata := map[string]string{
				"package_manager": "pip",
				"source_file":     filepath.Base(path),
				"version_spec":    versionSpec,
			}

			artifact := p.CreateArtifact(
				name,
				versionSpec,
				artifact.TypePythonPackage,
				path,
				source,
				metadata,
			)
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}

// parsePipfileLock parses a Pipfile.lock file
func (p *PythonScanner) parsePipfileLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var lockData struct {
		Default map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
			Index   string   `json:"index"`
		} `json:"default"`
		Develop map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
			Index   string   `json:"index"`
		} `json:"develop"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts, err
	}

	// Parse default dependencies
	for name, dep := range lockData.Default {
		metadata := map[string]string{
			"package_manager": "pipenv",
			"source_file":     PipfileLockFile,
			"dependency_type": "production",
			"index":           dep.Index,
		}

		if len(dep.Hashes) > 0 {
			metadata["hashes"] = strings.Join(dep.Hashes, ", ")
		}

		artifact := p.CreateArtifact(
			name,
			dep.Version,
			artifact.TypePythonPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	// Parse development dependencies
	for name, dep := range lockData.Develop {
		metadata := map[string]string{
			"package_manager": "pipenv",
			"source_file":     PipfileLockFile,
			"dependency_type": "development",
			"index":           dep.Index,
		}

		if len(dep.Hashes) > 0 {
			metadata["hashes"] = strings.Join(dep.Hashes, ", ")
		}

		artifact := p.CreateArtifact(
			name,
			dep.Version,
			artifact.TypePythonPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// parseSetupPy parses a setup.py file
func (p *PythonScanner) parseSetupPy(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		return artifacts, err
	}

	contentStr := string(content)

	// Extract install_requires dependencies
	installRequiresRegex := regexp.MustCompile(`install_requires\s*=\s*\[(.*?)\]`)
	matches := installRequiresRegex.FindStringSubmatch(contentStr)

	if matches != nil {
		requiresStr := matches[1]

		// Extract individual package names
		packageRegex := regexp.MustCompile(`['"]([^'"]+)['"]`)
		packageMatches := packageRegex.FindAllStringSubmatch(requiresStr, -1)

		for _, match := range packageMatches {
			requirement := match[1]

			// Parse package name and version
			parts := regexp.MustCompile(`([a-zA-Z0-9_-]+)([<>=!~].*)?`).FindStringSubmatch(requirement)
			if parts != nil {
				name := parts[1]
				versionSpec := ""
				if len(parts) > 2 {
					versionSpec = parts[2]
				}

				metadata := map[string]string{
					"package_manager": "setuptools",
					"source_file":     SetupPyFile,
					"dependency_type": "install_requires",
					"version_spec":    versionSpec,
				}

				artifact := p.CreateArtifact(
					name,
					versionSpec,
					artifact.TypePythonPackage,
					path,
					source,
					metadata,
				)
				artifacts = append(artifacts, artifact)
			}
		}
	}

	return artifacts, nil
}

// parsePoetryLock parses a poetry.lock file
func (p *PythonScanner) parsePoetryLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	// Poetry.lock is in TOML format, but for simplicity we'll do basic parsing
	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentPackage string
	var currentVersion string
	var currentCategory string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[[package]]") {
			// Save previous package if exists
			if currentPackage != "" {
				metadata := map[string]string{
					"package_manager": "poetry",
					"source_file":     PoetryLockFile,
					"category":        currentCategory,
				}

				artifact := p.CreateArtifact(
					currentPackage,
					currentVersion,
					artifact.TypePythonPackage,
					path,
					source,
					metadata,
				)
				artifacts = append(artifacts, artifact)
			}

			// Reset for new package
			currentPackage = ""
			currentVersion = ""
			currentCategory = ""
		} else if strings.HasPrefix(line, "name = ") {
			currentPackage = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		} else if strings.HasPrefix(line, "category = ") {
			currentCategory = strings.Trim(strings.TrimPrefix(line, "category = "), `"`)
		}
	}

	// Save last package
	if currentPackage != "" {
		metadata := map[string]string{
			"package_manager": "poetry",
			"source_file":     PoetryLockFile,
			"category":        currentCategory,
		}

		artifact := p.CreateArtifact(
			currentPackage,
			currentVersion,
			artifact.TypePythonPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// parseCondaEnvironment parses a conda environment.yml file
func (p *PythonScanner) parseCondaEnvironment(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inDependencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "dependencies:" {
			inDependencies = true
			continue
		}

		if inDependencies {
			if strings.HasPrefix(line, "- ") {
				dep := strings.TrimPrefix(line, "- ")

				// Parse package name and version
				parts := strings.Split(dep, "=")
				name := strings.TrimSpace(parts[0])
				version := ""
				if len(parts) > 1 {
					version = strings.TrimSpace(parts[1])
				}

				metadata := map[string]string{
					"package_manager": "conda",
					"source_file":     CondaYamlFile,
				}

				artifact := p.CreateArtifact(
					name,
					version,
					artifact.TypeCondaPackage,
					path,
					source,
					metadata,
				)
				artifacts = append(artifacts, artifact)
			} else if !strings.HasPrefix(line, " ") {
				// End of dependencies section
				break
			}
		}
	}

	return artifacts, nil
}

// parsePyprojectToml parses a pyproject.toml file
func (p *PythonScanner) parsePyprojectToml(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	// For simplicity, we'll do basic TOML parsing
	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		return artifacts, err
	}

	contentStr := string(content)

	// Extract dependencies from poetry or setuptools sections
	dependenciesRegex := regexp.MustCompile(`dependencies\s*=\s*\[(.*?)\]`)
	matches := dependenciesRegex.FindStringSubmatch(contentStr)

	if matches != nil {
		depsStr := matches[1]

		// Extract individual package names
		packageRegex := regexp.MustCompile(`['"]([^'"]+)['"]`)
		packageMatches := packageRegex.FindAllStringSubmatch(depsStr, -1)

		for _, match := range packageMatches {
			requirement := match[1]

			// Parse package name and version
			parts := regexp.MustCompile(`([a-zA-Z0-9_-]+)([<>=!~].*)?`).FindStringSubmatch(requirement)
			if parts != nil {
				name := parts[1]
				versionSpec := ""
				if len(parts) > 2 {
					versionSpec = parts[2]
				}

				metadata := map[string]string{
					"package_manager": "pip",
					"source_file":     PyprojectTomlFile,
					"version_spec":    versionSpec,
				}

				artifact := p.CreateArtifact(
					name,
					versionSpec,
					artifact.TypePythonPackage,
					path,
					source,
					metadata,
				)
				artifacts = append(artifacts, artifact)
			}
		}
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (p *PythonScanner) CanScan(path string, filename string) bool {
	return p.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (p *PythonScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case RequirementsTxtFile:
		return p.parseRequirementsTxt(path, source)
	case PipfileLockFile:
		return p.parsePipfileLock(path, source)
	case SetupPyFile:
		return p.parseSetupPy(path, source)
	case PyprojectTomlFile:
		return p.parsePyprojectToml(path, source)
	case PoetryLockFile:
		return p.parsePoetryLock(path, source)
	case CondaYamlFile:
		return p.parseCondaEnvironment(path, source)
	default:
		// Handle requirements-*.txt patterns
		if strings.HasPrefix(filename, "requirements") && strings.HasSuffix(filename, ".txt") {
			return p.parseRequirementsTxt(path, source)
		}
	}

	return nil, nil
}
