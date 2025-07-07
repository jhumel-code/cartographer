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
	YarnLockFile    = "yarn.lock"
	PackageJsonFile = "package.json"
)

// YarnPackageJson represents the structure of package.json for Yarn workspaces
type YarnPackageJson struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Workspaces      []string          `json:"workspaces"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// YarnScanner scans for Yarn (JavaScript) dependencies
type YarnScanner struct {
	*core.BaseScanner
}

// NewYarnScanner creates a new Yarn scanner
func NewYarnScanner() *YarnScanner {
	patterns := []string{
		YarnLockFile,
		PackageJsonFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeNpmPackage,
	}

	return &YarnScanner{
		BaseScanner: core.NewBaseScanner("yarn-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Yarn packages in the source
func (y *YarnScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return y.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !y.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case YarnLockFile:
			return y.parseYarnLock(path, source)
		case PackageJsonFile:
			// Only parse package.json if it's in a Yarn workspace (has yarn.lock nearby)
			if y.hasYarnLock(filepath.Dir(path)) {
				return y.parsePackageJson(path, source)
			}
		}

		return nil, nil
	})
}

// hasYarnLock checks if a directory contains yarn.lock
func (y *YarnScanner) hasYarnLock(dir string) bool {
	yarnLockPath := filepath.Join(dir, YarnLockFile)
	if _, err := os.Stat(yarnLockPath); err == nil {
		return true
	}

	// Check parent directories up to 3 levels
	for i := 0; i < 3; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		yarnLockPath = filepath.Join(parent, YarnLockFile)
		if _, err := os.Stat(yarnLockPath); err == nil {
			return true
		}

		dir = parent
	}

	return false
}

// parseYarnLock parses a yarn.lock file
func (y *YarnScanner) parseYarnLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^"?([^@\s]+)@([^"]+)"?:`)
	versionRegex := regexp.MustCompile(`^\s+version\s+"([^"]+)"`)

	var currentPackage, currentVersion string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Check for package declaration
		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			// Save previous package if exists
			if currentPackage != "" && currentVersion != "" {
				artifacts = append(artifacts, y.createYarnArtifact(currentPackage, currentVersion, path, source))
			}

			currentPackage = matches[1]
			currentVersion = ""
		}

		// Check for version line
		if matches := versionRegex.FindStringSubmatch(line); matches != nil {
			currentVersion = matches[1]
		}
	}

	// Save last package
	if currentPackage != "" && currentVersion != "" {
		artifacts = append(artifacts, y.createYarnArtifact(currentPackage, currentVersion, path, source))
	}

	return artifacts, nil
}

// createYarnArtifact creates a Yarn package artifact
func (y *YarnScanner) createYarnArtifact(name, version, path string, source artifact.Source) artifact.Artifact {
	metadata := map[string]string{
		"package_manager": "yarn",
		"source_file":     YarnLockFile,
	}

	return y.CreateArtifact(
		name,
		version,
		artifact.TypeNpmPackage,
		path,
		source,
		metadata,
	)
}

// parsePackageJson parses package.json for Yarn workspace information
func (y *YarnScanner) parsePackageJson(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var packageJson YarnPackageJson
	if err := json.NewDecoder(file).Decode(&packageJson); err != nil {
		return artifacts, err
	}

	// Only create artifact for the main package if it has a name
	if packageJson.Name != "" {
		metadata := map[string]string{
			"package_manager": "yarn",
			"source_file":     PackageJsonFile,
			"is_workspace":    "false",
		}

		// Check if this is a Yarn workspace root
		if len(packageJson.Workspaces) > 0 {
			metadata["is_workspace"] = "true"
		}

		artifact := y.CreateArtifact(
			packageJson.Name,
			packageJson.Version,
			artifact.TypeNpmPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (y *YarnScanner) CanScan(path string, filename string) bool {
	return y.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (y *YarnScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case YarnLockFile:
		return y.parseYarnLock(path, source)
	case PackageJsonFile:
		if y.hasYarnLock(filepath.Dir(path)) {
			return y.parsePackageJson(path, source)
		}
	}

	return nil, nil
}
