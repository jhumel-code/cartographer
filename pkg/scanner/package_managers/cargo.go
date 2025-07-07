package package_managers

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
)

const (
	CargoTomlFile = "Cargo.toml"
	CargoLockFile = "Cargo.lock"
	NamePrefix    = "name = "
	VersionPrefix = "version = "
	SourcePrefix  = "source = "
)

// CargoScanner scans for Rust Cargo dependencies
type CargoScanner struct {
	*core.BaseScanner
}

// NewCargoScanner creates a new Cargo scanner
func NewCargoScanner() *CargoScanner {
	patterns := []string{
		CargoTomlFile,
		CargoLockFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeRustCrate,
	}

	return &CargoScanner{
		BaseScanner: core.NewBaseScanner("cargo-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Cargo packages in the source
func (c *CargoScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return c.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !c.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case CargoTomlFile:
			return c.parseCargoToml(path, source)
		case CargoLockFile:
			return c.parseCargoLock(path, source)
		}

		return nil, nil
	})
}

// parseCargoToml parses a Cargo.toml file
func (c *CargoScanner) parseCargoToml(path string, source artifact.Source) ([]artifact.Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	parser := &cargoTomlParser{
		scanner:         c,
		path:            path,
		source:          source,
		dependencyRegex: regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*=\s*(.+)$`),
		versionRegex:    regexp.MustCompile(`"([^"]+)"`),
	}

	return parser.parse(file)
}

// cargoTomlParser handles parsing of Cargo.toml files
type cargoTomlParser struct {
	scanner         *CargoScanner
	path            string
	source          artifact.Source
	dependencyRegex *regexp.Regexp
	versionRegex    *regexp.Regexp

	currentSection string
	packageName    string
	packageVersion string
	artifacts      []artifact.Artifact
}

// parse processes the Cargo.toml file
func (p *cargoTomlParser) parse(file *os.File) ([]artifact.Artifact, error) {
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if p.shouldSkipLine(line) {
			continue
		}

		if p.isSection(line) {
			p.currentSection = strings.Trim(line, "[]")
			continue
		}

		p.processLine(line)
	}

	p.addMainPackageArtifact()
	return p.artifacts, scanner.Err()
}

// shouldSkipLine determines if a line should be skipped
func (p *cargoTomlParser) shouldSkipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// isSection determines if a line defines a TOML section
func (p *cargoTomlParser) isSection(line string) bool {
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
}

// processLine processes a single line based on current section
func (p *cargoTomlParser) processLine(line string) {
	switch p.currentSection {
	case "package":
		p.parsePackageInfo(line)
	case "dependencies", "dev-dependencies", "build-dependencies":
		p.parseDependency(line)
	}
}

// parsePackageInfo extracts package name and version
func (p *cargoTomlParser) parsePackageInfo(line string) {
	if strings.HasPrefix(line, NamePrefix) {
		if matches := p.versionRegex.FindStringSubmatch(line); matches != nil {
			p.packageName = matches[1]
		}
	} else if strings.HasPrefix(line, VersionPrefix) {
		if matches := p.versionRegex.FindStringSubmatch(line); matches != nil {
			p.packageVersion = matches[1]
		}
	}
}

// parseDependency extracts dependency information
func (p *cargoTomlParser) parseDependency(line string) {
	matches := p.dependencyRegex.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	name := matches[1]
	versionSpec := matches[2]

	// Extract version from various formats
	if versionMatches := p.versionRegex.FindStringSubmatch(versionSpec); versionMatches != nil {
		versionSpec = versionMatches[1]
	}

	depType := p.getDependencyType()
	metadata := p.createDependencyMetadata(depType)

	artifact := p.scanner.CreateArtifact(
		name,
		versionSpec,
		artifact.TypeRustCrate,
		p.path,
		p.source,
		metadata,
	)
	p.artifacts = append(p.artifacts, artifact)
}

// getDependencyType returns the dependency type based on current section
func (p *cargoTomlParser) getDependencyType() string {
	switch p.currentSection {
	case "dev-dependencies":
		return "development"
	case "build-dependencies":
		return "build"
	default:
		return "normal"
	}
}

// createDependencyMetadata creates metadata for dependencies
func (p *cargoTomlParser) createDependencyMetadata(depType string) map[string]string {
	return map[string]string{
		"package_manager": "cargo",
		"source_file":     CargoTomlFile,
		"dependency_type": depType,
	}
}

// addMainPackageArtifact adds the main package artifact if found
func (p *cargoTomlParser) addMainPackageArtifact() {
	if p.packageName == "" {
		return
	}

	metadata := map[string]string{
		"package_manager": "cargo",
		"source_file":     CargoTomlFile,
		"is_main_crate":   "true",
	}

	mainArtifact := p.scanner.CreateArtifact(
		p.packageName,
		p.packageVersion,
		artifact.TypeRustCrate,
		p.path,
		p.source,
		metadata,
	)
	p.artifacts = append(p.artifacts, mainArtifact)
}

// parseCargoLock parses a Cargo.lock file
func (c *CargoScanner) parseCargoLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	parser := &cargoLockParser{
		scanner: c,
		path:    path,
		source:  source,
	}

	return parser.parse(file)
}

// cargoLockParser handles parsing of Cargo.lock files
type cargoLockParser struct {
	scanner *CargoScanner
	path    string
	source  artifact.Source

	currentSection string
	currentName    string
	currentVersion string
	currentSource  string
	artifacts      []artifact.Artifact
}

// parse processes the Cargo.lock file
func (p *cargoLockParser) parse(file *os.File) ([]artifact.Artifact, error) {
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if p.shouldSkipLine(line) {
			continue
		}

		if p.isPackageSection(line) {
			p.saveCurrentPackage()
			p.resetCurrentPackage()
			continue
		}

		p.processPackageLine(line)
	}

	// Save the last package
	p.saveCurrentPackage()
	return p.artifacts, scanner.Err()
}

// shouldSkipLine determines if a line should be skipped
func (p *cargoLockParser) shouldSkipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// isPackageSection determines if a line starts a new package section
func (p *cargoLockParser) isPackageSection(line string) bool {
	return line == "[[package]]"
}

// resetCurrentPackage resets the current package state
func (p *cargoLockParser) resetCurrentPackage() {
	p.currentName = ""
	p.currentVersion = ""
	p.currentSource = ""
	p.currentSection = "package"
}

// processPackageLine processes a line within a package section
func (p *cargoLockParser) processPackageLine(line string) {
	if p.currentSection != "package" {
		return
	}

	if strings.HasPrefix(line, NamePrefix) {
		p.currentName = strings.Trim(strings.TrimPrefix(line, NamePrefix), `"`)
	} else if strings.HasPrefix(line, VersionPrefix) {
		p.currentVersion = strings.Trim(strings.TrimPrefix(line, VersionPrefix), `"`)
	} else if strings.HasPrefix(line, SourcePrefix) {
		p.currentSource = strings.Trim(strings.TrimPrefix(line, SourcePrefix), `"`)
	}
}

// saveCurrentPackage saves the current package as an artifact
func (p *cargoLockParser) saveCurrentPackage() {
	if p.currentName == "" {
		return
	}

	metadata := map[string]string{
		"package_manager": "cargo",
		"source_file":     CargoLockFile,
		"source":          p.currentSource,
	}

	artifact := p.scanner.CreateArtifact(
		p.currentName,
		p.currentVersion,
		artifact.TypeRustCrate,
		p.path,
		p.source,
		metadata,
	)
	p.artifacts = append(p.artifacts, artifact)
}

// CanScan determines if this scanner can handle the given file
func (c *CargoScanner) CanScan(path string, filename string) bool {
	return c.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (c *CargoScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case CargoTomlFile:
		return c.parseCargoToml(path, source)
	case CargoLockFile:
		return c.parseCargoLock(path, source)
	}

	return nil, nil
}
