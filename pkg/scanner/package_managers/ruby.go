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
	GemfileFile     = "Gemfile"
	GemfileLockFile = "Gemfile.lock"
	GemspecFile     = "*.gemspec"
)

// GemScanner scans for Ruby Gem dependencies
type GemScanner struct {
	*core.BaseScanner
}

// NewGemScanner creates a new Gem scanner
func NewGemScanner() *GemScanner {
	patterns := []string{
		GemfileFile,
		GemfileLockFile,
		GemspecFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeRubyGem,
	}

	return &GemScanner{
		BaseScanner: core.NewBaseScanner("gem-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Ruby gems in the source
func (g *GemScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return g.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !g.MatchesFile(filename, path) {
			return nil, nil
		}

		switch filename {
		case GemfileFile:
			return g.parseGemfile(path, source)
		case GemfileLockFile:
			return g.parseGemfileLock(path, source)
		default:
			if strings.HasSuffix(filename, ".gemspec") {
				return g.parseGemspec(path, source)
			}
		}

		return nil, nil
	})
}

// parseGemfile parses a Gemfile
func (g *GemScanner) parseGemfile(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	gemRegex := regexp.MustCompile(`gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := gemRegex.FindStringSubmatch(line)
		if matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
			}

			metadata := map[string]string{
				"package_manager": "bundler",
				"source_file":     GemfileFile,
			}

			artifact := g.CreateArtifact(
				name,
				version,
				artifact.TypeRubyGem,
				path,
				source,
				metadata,
			)
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}

// parseGemfileLock parses a Gemfile.lock
func (g *GemScanner) parseGemfileLock(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inSpecs := false
	gemRegex := regexp.MustCompile(`^\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if inSpecs && strings.HasPrefix(line, "  ") {
			matches := gemRegex.FindStringSubmatch(line)
			if matches != nil {
				name := matches[1]
				version := matches[2]

				metadata := map[string]string{
					"package_manager": "bundler",
					"source_file":     GemfileLockFile,
				}

				artifact := g.CreateArtifact(
					name,
					version,
					artifact.TypeRubyGem,
					path,
					source,
					metadata,
				)
				artifacts = append(artifacts, artifact)
			}
		} else if inSpecs && !strings.HasPrefix(line, " ") {
			// End of specs section
			break
		}
	}

	return artifacts, nil
}

// parseGemspec parses a .gemspec file
func (g *GemScanner) parseGemspec(path string, source artifact.Source) ([]artifact.Artifact, error) {
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

	// Extract gem name and version
	nameRegex := regexp.MustCompile(`(?m)^\s*s\.name\s*=\s*['"]([^'"]+)['"]`)
	versionRegex := regexp.MustCompile(`(?m)^\s*s\.version\s*=\s*['"]([^'"]+)['"]`)

	nameMatches := nameRegex.FindStringSubmatch(contentStr)
	versionMatches := versionRegex.FindStringSubmatch(contentStr)

	if nameMatches != nil {
		name := nameMatches[1]
		version := ""
		if versionMatches != nil {
			version = versionMatches[1]
		}

		metadata := map[string]string{
			"package_manager": "gem",
			"source_file":     filepath.Base(path),
			"is_gemspec":      "true",
		}

		artifact := g.CreateArtifact(
			name,
			version,
			artifact.TypeRubyGem,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (g *GemScanner) CanScan(path string, filename string) bool {
	return g.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (g *GemScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	switch filename {
	case GemfileFile:
		return g.parseGemfile(path, source)
	case GemfileLockFile:
		return g.parseGemfileLock(path, source)
	default:
		if strings.HasSuffix(filename, ".gemspec") {
			return g.parseGemspec(path, source)
		}
	}

	return nil, nil
}
