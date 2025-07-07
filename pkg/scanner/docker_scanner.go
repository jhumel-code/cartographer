package scanner

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/docker"
)

// DockerImageScanner handles scanning of Docker images
type DockerImageScanner struct {
	dockerClient   *docker.Client
	scanners       []artifact.Scanner
	pluginRegistry *PluginRegistry
}

// NewDockerImageScanner creates a new Docker image scanner
func NewDockerImageScanner(dockerClient *docker.Client, scanners []artifact.Scanner, pluginRegistry *PluginRegistry) *DockerImageScanner {
	return &DockerImageScanner{
		dockerClient:   dockerClient,
		scanners:       scanners,
		pluginRegistry: pluginRegistry,
	}
}

// Scan scans a Docker image for artifacts
func (s *DockerImageScanner) Scan(ctx context.Context, imageRef string) (*artifact.Collection, error) {
	startTime := time.Now()

	imageInfo, image, err := s.dockerClient.PullImage(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("pulling image: %w", err)
	}

	source := artifact.Source{
		Type:     artifact.SourceTypeDockerImage,
		Location: imageRef,
		Metadata: map[string]string{
			"registry":     imageInfo.Registry,
			"repository":   imageInfo.Repository,
			"tag":          imageInfo.Tag,
			"digest":       imageInfo.Digest,
			"architecture": imageInfo.Architecture,
			"os":           imageInfo.OS,
		},
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}

	var allArtifacts []artifact.Artifact
	for i, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			continue
		}

		layerSource := source
		layerSource.Layer = layerDigest.String()
		layerSource.Metadata["layer_index"] = fmt.Sprintf("%d", i)

		layerArtifacts, err := s.scanLayer(ctx, layer, layerSource)
		if err != nil {
			continue
		}

		allArtifacts = append(allArtifacts, layerArtifacts...)
	}

	// Assign unique IDs and process through plugins
	allArtifacts = assignArtifactIDs(allArtifacts)
	enhancedArtifacts, err := s.pluginRegistry.ProcessArtifacts(ctx, allArtifacts)
	if err != nil {
		enhancedArtifacts = allArtifacts
	}

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        generateCollectionID(imageRef),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: enhancedArtifacts,
		Summary:   generateSummary(enhancedArtifacts, scanDuration),
		Metadata: map[string]string{
			"scanner_version": "1.0.0",
			"scan_type":       "docker-image",
		},
	}, nil
}

// scanLayer scans a single Docker layer
func (s *DockerImageScanner) scanLayer(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	var allArtifacts []artifact.Artifact

	// Run scanners that implement LayerScanner interface
	for _, scanner := range s.scanners {
		if layerScanner, ok := scanner.(LayerScanner); ok {
			content, err := layer.Uncompressed()
			if err != nil {
				continue
			}

			artifacts, err := layerScanner.ScanLayer(ctx, content, source)
			content.Close()
			if err != nil {
				continue
			}

			allArtifacts = append(allArtifacts, artifacts...)
		}
	}

	return allArtifacts, nil
}
