package scanner

import (
	"context"
	"time"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// FilesystemScanner handles scanning of filesystem paths
type FilesystemScanner struct {
	scanners       []artifact.Scanner
	pluginRegistry *PluginRegistry
}

// NewFilesystemScanner creates a new filesystem scanner
func NewFilesystemScanner(scanners []artifact.Scanner, pluginRegistry *PluginRegistry) *FilesystemScanner {
	return &FilesystemScanner{
		scanners:       scanners,
		pluginRegistry: pluginRegistry,
	}
}

// Scan scans a filesystem path for artifacts
func (s *FilesystemScanner) Scan(ctx context.Context, path string) (*artifact.Collection, error) {
	startTime := time.Now()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: path,
		Metadata: map[string]string{
			"scan_type": "filesystem",
		},
	}

	var allArtifacts []artifact.Artifact
	for _, scanner := range s.scanners {
		// Skip layer scanners for filesystem scanning
		if _, ok := scanner.(LayerScanner); ok {
			continue
		}

		artifacts, err := scanner.Scan(ctx, source)
		if err != nil {
			continue // Skip failed scanners
		}

		allArtifacts = append(allArtifacts, artifacts...)
	}

	// Assign unique IDs and process through plugins
	allArtifacts = assignArtifactIDs(allArtifacts)
	enhancedArtifacts, err := s.pluginRegistry.ProcessArtifacts(ctx, allArtifacts)
	if err != nil {
		enhancedArtifacts = allArtifacts
	}

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        generateCollectionID(path),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: enhancedArtifacts,
		Summary:   generateSummary(enhancedArtifacts, scanDuration),
		Metadata: map[string]string{
			"scanner_version": "1.0.0",
			"scan_type":       "filesystem",
		},
	}, nil
}
