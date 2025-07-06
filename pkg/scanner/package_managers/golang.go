package package_managers

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

const (
	GoModFile     = "go.mod"
	GoSumFile     = "go.sum"
	RequirePrefix = "require "
	RequireBlock  = "require ("
)

// GoScanner scans for Go module dependencies
type GoScanner struct {
	*core.BaseScanner
}

// NewGoScanner creates a new Go scanner
func NewGoScanner() *GoScanner {
	patterns := []string{
		GoModFile,
		GoSumFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeGoModule,
	}

	return &GoScanner{
		BaseScanner: core.NewBaseScanner("go-mod-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Go modules in the source
func (g *GoScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return g.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !g.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case GoModFile:
			return g.parseGoMod(path, source)
		case GoSumFile:
			return g.parseGoSum(path, source)
		}

		return nil, nil
	})
}

// parseGoMod parses a go.mod file
func (g *GoScanner) parseGoMod(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	parser := &goModParser{
		scanner: g,
		path:    path,
		source:  source,
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		artifacts = append(artifacts, parser.parseLine(line)...)
	}

	// Add main module if found
	if parser.moduleName != "" {
		mainModule := g.createMainModuleArtifact(parser.moduleName, parser.moduleVersion, path, source)
		artifacts = append(artifacts, mainModule)
	}

	return artifacts, nil
}

// goModParser helper struct to manage parsing state
type goModParser struct {
	scanner        *GoScanner
	path           string
	source         artifact.Source
	inRequireBlock bool
	moduleName     string
	moduleVersion  string
	requireRegex   *regexp.Regexp
	moduleRegex    *regexp.Regexp
}

// parseLine processes a single line from go.mod
func (p *goModParser) parseLine(line string) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// Initialize regexes if needed
	if p.requireRegex == nil {
		p.requireRegex = regexp.MustCompile(`^\s*([^\s]+)\s+([^\s]+)(?:\s+//.*)?$`)
		p.moduleRegex = regexp.MustCompile(`^module\s+([^\s]+)`)
	}

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "//") {
		return artifacts
	}

	// Parse module declaration
	if matches := p.moduleRegex.FindStringSubmatch(line); matches != nil {
		p.moduleName = matches[1]
		return artifacts
	}

	// Handle require block start/end
	if strings.HasPrefix(line, RequireBlock) {
		p.inRequireBlock = true
		return artifacts
	}

	if p.inRequireBlock && line == ")" {
		p.inRequireBlock = false
		return artifacts
	}

	// Parse require statements
	if strings.HasPrefix(line, RequirePrefix) || p.inRequireBlock {
		return p.parseRequire(line)
	}

	return artifacts
}

// parseRequire parses a require statement
func (p *goModParser) parseRequire(line string) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// Remove require prefix for single line requires
	line = strings.TrimPrefix(line, RequirePrefix)

	matches := p.requireRegex.FindStringSubmatch(line)
	if matches != nil {
		name := matches[1]
		version := matches[2]

		metadata := map[string]string{
			"package_manager": "go",
			"source_file":     GoModFile,
		}

		artifact := p.scanner.CreateArtifact(
			name,
			version,
			artifact.TypeGoModule,
			p.path,
			p.source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

// createMainModuleArtifact creates an artifact for the main module
func (g *GoScanner) createMainModuleArtifact(moduleName, moduleVersion, path string, source artifact.Source) artifact.Artifact {
	metadata := map[string]string{
		"package_manager": "go",
		"source_file":     GoModFile,
		"is_main_module":  "true",
	}

	return g.CreateArtifact(
		moduleName,
		moduleVersion,
		artifact.TypeGoModule,
		path,
		source,
		metadata,
	)
}

// parseGoSum parses a go.sum file
func (g *GoScanner) parseGoSum(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	sumRegex := regexp.MustCompile(`^([^\s]+)\s+([^\s]+)\s+([^\s]+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		matches := sumRegex.FindStringSubmatch(line)
		if matches != nil {
			name := matches[1]
			version := matches[2]
			checksum := matches[3]

			metadata := map[string]string{
				"package_manager": "go",
				"source_file":     GoSumFile,
				"checksum":        checksum,
			}

			artifact := g.CreateArtifact(
				name,
				version,
				artifact.TypeGoModule,
				path,
				source,
				metadata,
			)
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (g *GoScanner) CanScan(path string, filename string) bool {
	return g.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (g *GoScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case GoModFile:
		return g.parseGoMod(path, source)
	case GoSumFile:
		return g.parseGoSum(path, source)
	}

	return nil, nil
}
