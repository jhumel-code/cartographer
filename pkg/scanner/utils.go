package scanner

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// generateCollectionID generates a unique ID for a collection
func generateCollectionID(source string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", source, time.Now().UnixNano())))
	return fmt.Sprintf("%x", hash)[:12]
}

// generateSummary creates a summary of the scan results
func generateSummary(artifacts []artifact.Artifact, duration time.Duration) artifact.Summary {
	summary := artifact.Summary{
		TotalArtifacts:  len(artifacts),
		ScanDuration:    artifact.Duration{Duration: duration},
		ArtifactsByType: make(map[artifact.Type]int),
		LicenseCount:    make(map[string]int),
	}

	for _, art := range artifacts {
		summary.ArtifactsByType[art.Type]++
	}

	return summary
}

// assignArtifactIDs assigns unique IDs to all artifacts
func assignArtifactIDs(artifacts []artifact.Artifact) []artifact.Artifact {
	for i := range artifacts {
		artifacts[i].ID = generateArtifactID(&artifacts[i])
	}
	return artifacts
}

// generateArtifactID generates a unique ID for an artifact
func generateArtifactID(art *artifact.Artifact) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s-%d",
		art.Name, art.Path, art.Source.Location, time.Now().UnixNano())))
	return fmt.Sprintf("%x", hash)[:12]
}
