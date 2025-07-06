package package_managers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

const (
	ComposerJsonFile = "composer.json"
	ComposerLockFile = "composer.lock"
)

// ComposerScanner scans for PHP Composer dependencies
type ComposerScanner struct {
	*core.BaseScanner
}

// NewComposerScanner creates a new Composer scanner
func NewComposerScanner() *ComposerScanner {
	patterns := []string{
		ComposerJsonFile,
		ComposerLockFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypePHPPackage,
	}

	return &ComposerScanner{
		BaseScanner: core.NewBaseScanner("composer-scanner", supportedTypes, patterns),
	}
}

// ComposerJson represents the structure of composer.json
type ComposerJson struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Version      string            `json:"version"`
	Type         string            `json:"type"`
	License      []string          `json:"license"`
	Require      map[string]string `json:"require"`
	RequireDev   map[string]string `json:"require-dev"`
	AutoloadPSR4 map[string]string `json:"autoload>psr-4"`
}

// ComposerLock represents the structure of composer.lock
type ComposerLock struct {
	ReadmeText  string                `json:"_readme"`
	Packages    []ComposerLockPackage `json:"packages"`
	PackagesDev []ComposerLockPackage `json:"packages-dev"`
	Platform    map[string]string     `json:"platform"`
}

// ComposerLockPackage represents a package in composer.lock
type ComposerLockPackage struct {
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Source      ComposerSource `json:"source"`
	Dist        ComposerDist   `json:"dist"`
	Type        string         `json:"type"`
	License     []string       `json:"license"`
	Description string         `json:"description"`
	Time        string         `json:"time"`
}

// ComposerSource represents source information
type ComposerSource struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

// ComposerDist represents distribution information
type ComposerDist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum"`
}

// Scan scans for Composer packages in the source
func (c *ComposerScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return c.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !c.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case ComposerJsonFile:
			return c.parseComposerJson(path, source)
		case ComposerLockFile:
			return c.parseComposerLock(path, source)
		}

		return nil, nil
	})
}

// parseComposerJson parses a composer.json file
func (c *ComposerScanner) parseComposerJson(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var composer ComposerJson
	if err := json.NewDecoder(file).Decode(&composer); err != nil {
		return artifacts, err
	}

	// Create artifact for the main package
	if composer.Name != "" {
		metadata := map[string]string{
			"package_manager": "composer",
			"source_file":     ComposerJsonFile,
			"type":            composer.Type,
			"description":     composer.Description,
		}

		if len(composer.License) > 0 {
			metadata["license"] = composer.License[0]
		}

		mainArtifact := c.CreateArtifact(
			composer.Name,
			composer.Version,
			artifact.TypePHPPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, mainArtifact)
	}

	// Parse dependencies
	for name, version := range composer.Require {
		// Skip PHP version constraints
		if name == "php" {
			continue
		}

		metadata := map[string]string{
			"package_manager": "composer",
			"source_file":     ComposerJsonFile,
			"dependency_type": "require",
		}

		depArtifact := c.CreateArtifact(
			name,
			version,
			artifact.TypePHPPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, depArtifact)
	}

	// Parse dev dependencies
	for name, version := range composer.RequireDev {
		if name == "php" {
			continue
		}

		metadata := map[string]string{
			"package_manager": "composer",
			"source_file":     ComposerJsonFile,
			"dependency_type": "require-dev",
		}

		depArtifact := c.CreateArtifact(
			name,
			version,
			artifact.TypePHPPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, depArtifact)
	}

	return artifacts, nil
}

// parseComposerLock parses a composer.lock file
func (c *ComposerScanner) parseComposerLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var lock ComposerLock
	if err := json.NewDecoder(file).Decode(&lock); err != nil {
		return artifacts, err
	}

	// Parse production packages
	for _, pkg := range lock.Packages {
		metadata := map[string]string{
			"package_manager": "composer",
			"source_file":     ComposerLockFile,
			"dependency_type": "production",
			"type":            pkg.Type,
			"description":     pkg.Description,
			"time":            pkg.Time,
		}

		if len(pkg.License) > 0 {
			metadata["license"] = pkg.License[0]
		}

		if pkg.Source.Type != "" {
			metadata["source_type"] = pkg.Source.Type
			metadata["source_url"] = pkg.Source.URL
		}

		artifact := c.CreateArtifact(
			pkg.Name,
			pkg.Version,
			artifact.TypePHPPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	// Parse dev packages
	for _, pkg := range lock.PackagesDev {
		metadata := map[string]string{
			"package_manager": "composer",
			"source_file":     ComposerLockFile,
			"dependency_type": "development",
			"type":            pkg.Type,
			"description":     pkg.Description,
			"time":            pkg.Time,
		}

		if len(pkg.License) > 0 {
			metadata["license"] = pkg.License[0]
		}

		artifact := c.CreateArtifact(
			pkg.Name,
			pkg.Version,
			artifact.TypePHPPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (c *ComposerScanner) CanScan(path string, filename string) bool {
	return c.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (c *ComposerScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case ComposerJsonFile:
		return c.parseComposerJson(path, source)
	case ComposerLockFile:
		return c.parseComposerLock(path, source)
	}

	return nil, nil
}
