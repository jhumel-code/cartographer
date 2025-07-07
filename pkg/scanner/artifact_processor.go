package scanner

import (
	"context"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// ArtifactProcessor handles post-scan processing of artifacts
type ArtifactProcessor struct {
	pluginRegistry *PluginRegistry
}

// NewArtifactProcessor creates a new artifact processor
func NewArtifactProcessor(pluginRegistry *PluginRegistry) *ArtifactProcessor {
	return &ArtifactProcessor{
		pluginRegistry: pluginRegistry,
	}
}

// Process runs artifacts through the processing pipeline
func (p *ArtifactProcessor) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	// Assign unique IDs to artifacts
	artifacts = assignArtifactIDs(artifacts)

	// Process artifacts through plugins
	enhancedArtifacts, err := p.pluginRegistry.ProcessArtifacts(ctx, artifacts)
	if err != nil {
		// Continue with unprocessed artifacts if plugin processing fails
		enhancedArtifacts = artifacts
	}

	// Analyze relationships between artifacts
	relationshipAnalyzer := NewRelationshipAnalyzer()
	enhancedArtifacts = relationshipAnalyzer.AnalyzeRelationships(enhancedArtifacts)

	return enhancedArtifacts, nil
}
