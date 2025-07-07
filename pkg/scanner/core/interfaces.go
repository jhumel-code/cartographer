package core

import (
	"context"
	"io"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// Scanner defines the interface for all artifact scanners
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// SupportedTypes returns the artifact types this scanner can detect
	SupportedTypes() []artifact.Type

	// Scan scans the provided source for artifacts
	Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error)
}

// LayerScanner defines the interface for Docker layer scanners
type LayerScanner interface {
	// ScanLayer scans a Docker layer for artifacts
	ScanLayer(ctx context.Context, content io.Reader, source artifact.Source) ([]artifact.Artifact, error)
}

// FileScanner defines the interface for file-based scanners
type FileScanner interface {
	// CanScan determines if this scanner can handle the given file
	CanScan(path string, filename string) bool

	// ScanFile scans a specific file for artifacts
	ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error)
}

// DirectoryScanner defines the interface for directory-based scanners
type DirectoryScanner interface {
	// CanScanDirectory determines if this scanner can handle the given directory
	CanScanDirectory(path string) bool

	// ScanDirectory scans a directory for artifacts
	ScanDirectory(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error)
}

// PatternMatcher defines the interface for pattern-based file matching
type PatternMatcher interface {
	// MatchesFile returns true if the file matches the scanner's patterns
	MatchesFile(filename string, filepath string) bool

	// GetPatterns returns the file patterns this scanner supports
	GetPatterns() []string
}

// ConfigurableScanner defines the interface for scanners with configuration
type ConfigurableScanner interface {
	// Configure sets scanner-specific configuration
	Configure(config map[string]interface{}) error

	// GetConfig returns the current configuration
	GetConfig() map[string]interface{}
}

// ProgressReporter defines the interface for scanners that can report progress
type ProgressReporter interface {
	// SetProgressCallback sets a callback for progress reporting
	SetProgressCallback(callback func(completed, total int, message string))
}
