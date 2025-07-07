package package_managers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
)

const (
	PackageJSONFile     = "package.json"
	PackageLockJSONFile = "package-lock.json"
	ShrinkwrapJSONFile  = "npm-shrinkwrap.json"
)

// NPMScanner scans for NPM package dependencies
type NPMScanner struct {
	*core.BaseScanner
}

// NewNPMScanner creates a new NPM scanner
func NewNPMScanner() *NPMScanner {
	patterns := []string{
		PackageJSONFile,
		PackageLockJSONFile,
		ShrinkwrapJSONFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeNpmPackage,
	}

	return &NPMScanner{
		BaseScanner: core.NewBaseScanner("npm-scanner", supportedTypes, patterns),
	}
}

// Scan scans for NPM packages in the source
func (n *NPMScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return n.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !n.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case PackageJSONFile:
			return n.parsePackageJSON(path, source)
		case PackageLockJSONFile:
			return n.parsePackageLockJSON(path, source)
		case ShrinkwrapJSONFile:
			return n.parseShrinkwrapJSON(path, source)
		}

		return nil, nil
	})
}

// parsePackageJSON parses a package.json file
func (n *NPMScanner) parsePackageJSON(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var packageData struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		License              interface{}       `json:"license"`
		Description          string            `json:"description"`
		Keywords             []string          `json:"keywords"`
		Repository           interface{}       `json:"repository"`
		Author               interface{}       `json:"author"`
		Homepage             string            `json:"homepage"`
	}

	if err := json.NewDecoder(file).Decode(&packageData); err != nil {
		return artifacts, err
	}

	// Create artifact for the main package
	if packageData.Name != "" {
		metadata := map[string]string{
			"package_manager": "npm",
			"source_file":     PackageJSONFile,
			"description":     packageData.Description,
			"homepage":        packageData.Homepage,
		}

		if license := n.extractLicense(packageData.License); license != "" {
			metadata["license"] = license
		}

		if len(packageData.Keywords) > 0 {
			metadata["keywords"] = strings.Join(packageData.Keywords, ", ")
		}

		mainPackage := n.CreateArtifact(
			packageData.Name,
			packageData.Version,
			artifact.TypeNpmPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, mainPackage)
	}

	// Parse dependencies
	for name, version := range packageData.Dependencies {
		dep := n.createDependencyArtifact(name, version, "production", path, source)
		artifacts = append(artifacts, dep)
	}

	for name, version := range packageData.DevDependencies {
		dep := n.createDependencyArtifact(name, version, "development", path, source)
		artifacts = append(artifacts, dep)
	}

	for name, version := range packageData.PeerDependencies {
		dep := n.createDependencyArtifact(name, version, "peer", path, source)
		artifacts = append(artifacts, dep)
	}

	for name, version := range packageData.OptionalDependencies {
		dep := n.createDependencyArtifact(name, version, "optional", path, source)
		artifacts = append(artifacts, dep)
	}

	return artifacts, nil
}

// parsePackageLockJSON parses a package-lock.json file
func (n *NPMScanner) parsePackageLockJSON(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var lockData struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		LockfileVersion int    `json:"lockfileVersion"`
		Dependencies    map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Dev       bool   `json:"dev"`
			Optional  bool   `json:"optional"`
		} `json:"dependencies"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts, err
	}

	for name, dep := range lockData.Dependencies {
		depType := "production"
		if dep.Dev {
			depType = "development"
		}
		if dep.Optional {
			depType = "optional"
		}

		metadata := map[string]string{
			"package_manager":  "npm",
			"source_file":      PackageLockJSONFile,
			"dependency_type":  depType,
			"resolved":         dep.Resolved,
			"integrity":        dep.Integrity,
			"lockfile_version": string(rune(lockData.LockfileVersion)),
		}

		artifact := n.CreateArtifact(
			name,
			dep.Version,
			artifact.TypeNpmPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// parseShrinkwrapJSON parses an npm-shrinkwrap.json file
func (n *NPMScanner) parseShrinkwrapJSON(path string, source artifact.Source) ([]artifact.Artifact, error) {
	// Shrinkwrap format is similar to package-lock, so reuse the logic
	return n.parsePackageLockJSON(path, source)
}

// createDependencyArtifact creates an artifact for a dependency
func (n *NPMScanner) createDependencyArtifact(name, version, depType, path string, source artifact.Source) artifact.Artifact {
	metadata := map[string]string{
		"package_manager": "npm",
		"source_file":     PackageJSONFile,
		"dependency_type": depType,
	}

	return n.CreateArtifact(name, version, artifact.TypeNpmPackage, path, source, metadata)
}

// extractLicense extracts license information from various formats
func (n *NPMScanner) extractLicense(license interface{}) string {
	switch v := license.(type) {
	case string:
		return v
	case map[string]interface{}:
		if licenseType, ok := v["type"].(string); ok {
			return licenseType
		}
	case []interface{}:
		if len(v) > 0 {
			if first, ok := v[0].(string); ok {
				return first
			}
			if firstMap, ok := v[0].(map[string]interface{}); ok {
				if licenseType, ok := firstMap["type"].(string); ok {
					return licenseType
				}
			}
		}
	}
	return ""
}

// CanScan determines if this scanner can handle the given file
func (n *NPMScanner) CanScan(path string, filename string) bool {
	return n.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (n *NPMScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case PackageJSONFile:
		return n.parsePackageJSON(path, source)
	case PackageLockJSONFile:
		return n.parsePackageLockJSON(path, source)
	case ShrinkwrapJSONFile:
		return n.parseShrinkwrapJSON(path, source)
	}

	return nil, nil
}
