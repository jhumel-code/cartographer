package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// BaseScanner provides common functionality for all scanners
type BaseScanner struct {
	name             string
	supportedTypes   []artifact.Type
	filePatterns     []string
	progressCallback func(completed, total int, message string)
	config           map[string]interface{}
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner(name string, supportedTypes []artifact.Type, patterns []string) *BaseScanner {
	return &BaseScanner{
		name:           name,
		supportedTypes: supportedTypes,
		filePatterns:   patterns,
		config:         make(map[string]interface{}),
	}
}

// Name returns the scanner name
func (b *BaseScanner) Name() string {
	return b.name
}

// SupportedTypes returns the artifact types this scanner can detect
func (b *BaseScanner) SupportedTypes() []artifact.Type {
	return b.supportedTypes
}

// MatchesFile returns true if the file matches the scanner's patterns
func (b *BaseScanner) MatchesFile(filename string, filePath string) bool {
	for _, pattern := range b.filePatterns {
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
		if strings.Contains(strings.ToLower(filename), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// GetPatterns returns the file patterns this scanner supports
func (b *BaseScanner) GetPatterns() []string {
	return b.filePatterns
}

// Configure sets scanner-specific configuration
func (b *BaseScanner) Configure(config map[string]interface{}) error {
	b.config = config
	return nil
}

// GetConfig returns the current configuration
func (b *BaseScanner) GetConfig() map[string]interface{} {
	return b.config
}

// SetProgressCallback sets a callback for progress reporting
func (b *BaseScanner) SetProgressCallback(callback func(completed, total int, message string)) {
	b.progressCallback = callback
}

// ReportProgress reports progress if a callback is set
func (b *BaseScanner) ReportProgress(completed, total int, message string) {
	if b.progressCallback != nil {
		b.progressCallback(completed, total, message)
	}
}

// WalkDirectory is a helper method to walk through directory structures
func (b *BaseScanner) WalkDirectory(ctx context.Context, rootPath string, source artifact.Source, handler func(path string, info os.FileInfo) ([]artifact.Artifact, error)) ([]artifact.Artifact, error) {
	var allArtifacts []artifact.Artifact

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil || info.IsDir() {
			return nil
		}

		artifacts, err := handler(path, info)
		if err != nil {
			return nil // Continue on errors
		}

		allArtifacts = append(allArtifacts, artifacts...)
		return nil
	})

	return allArtifacts, err
}

// CreateArtifact is a helper method to create artifacts with common metadata
func (b *BaseScanner) CreateArtifact(name, version string, artifactType artifact.Type, path string, source artifact.Source, metadata map[string]string) artifact.Artifact {
	if metadata == nil {
		metadata = make(map[string]string)
	}

	// Add scanner information
	metadata["scanner"] = b.name
	metadata["scan_timestamp"] = time.Now().Format(time.RFC3339)

	return artifact.Artifact{
		Name:     name,
		Version:  version,
		Type:     artifactType,
		Path:     path,
		Source:   source,
		Metadata: metadata,
	}
}

// IsValidFile checks if a file exists and is readable
func (b *BaseScanner) IsValidFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// MatchesFileWithPath provides enhanced pattern matching that supports directory-based patterns
func (b *BaseScanner) MatchesFileWithPath(filePath, rootPath string) bool {
	filename := filepath.Base(filePath)
	relPath := b.getRelativePath(filePath, rootPath)

	for _, pattern := range b.filePatterns {
		if b.matchesSinglePattern(pattern, filename, relPath) {
			return true
		}
	}
	return false
}

// getRelativePath returns the relative path from root, using forward slashes for consistent matching
func (b *BaseScanner) getRelativePath(filePath, rootPath string) string {
	relPath, err := filepath.Rel(rootPath, filePath)
	if err != nil {
		relPath = filePath
	}
	return filepath.ToSlash(relPath)
}

// matchesSinglePattern checks if a file matches a single pattern
func (b *BaseScanner) matchesSinglePattern(pattern, filename, relPath string) bool {
	// Handle directory patterns like "bin/*"
	if strings.Contains(pattern, "/") {
		return b.matchesDirectoryPattern(pattern, relPath)
	}
	// Handle file extension patterns
	matched, _ := filepath.Match(pattern, filename)
	return matched
}

// matchesDirectoryPattern checks if the relative path matches a directory pattern
func (b *BaseScanner) matchesDirectoryPattern(pattern, relPath string) bool {
	if matched, _ := filepath.Match(pattern, relPath); matched {
		return true
	}
	// Also try with the pattern converted to OS-specific separators
	osPattern := filepath.FromSlash(pattern)
	matched, _ := filepath.Match(osPattern, relPath)
	return matched
}
