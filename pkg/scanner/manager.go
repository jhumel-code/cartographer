package scanner

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/docker"
)

// Manager coordinates multiple scanners to analyze sources
type Manager struct {
	scanners     []artifact.Scanner
	dockerClient *docker.Client
}

// NewManager creates a new scanner manager
func NewManager(dockerClient *docker.Client) *Manager {
	manager := &Manager{
		scanners:     make([]artifact.Scanner, 0),
		dockerClient: dockerClient,
	}

	// Register universal scanners for comprehensive artifact detection
	manager.RegisterScanner(NewTarLayerScanner())
	manager.RegisterScanner(NewBinaryAnalyzer())
	manager.RegisterScanner(NewDependencyAnalyzer())
	manager.RegisterScanner(NewSecurityAnalyzer())
	manager.RegisterScanner(NewInfrastructureAnalyzer())
	manager.RegisterScanner(NewLicenseAnalyzer())
	manager.RegisterScanner(NewCIAnalyzer())

	return manager
}

// RegisterScanner adds a scanner to the manager
func (m *Manager) RegisterScanner(scanner artifact.Scanner) {
	m.scanners = append(m.scanners, scanner)
}

// ScanDockerImage scans a Docker image for artifacts
func (m *Manager) ScanDockerImage(ctx context.Context, imageRef string) (*artifact.Collection, error) {
	startTime := time.Now()

	imageInfo, image, err := m.dockerClient.PullImage(ctx, imageRef)
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

		layerArtifacts, err := m.scanLayer(ctx, layer, layerSource)
		if err != nil {
			continue
		}

		allArtifacts = append(allArtifacts, layerArtifacts...)
	}

	// Assign unique IDs to artifacts
	allArtifacts = assignArtifactIDs(allArtifacts)

	// Analyze relationships between artifacts
	relationshipAnalyzer := NewRelationshipAnalyzer()
	allArtifacts = relationshipAnalyzer.AnalyzeRelationships(allArtifacts)

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        generateCollectionID(imageRef),
		Name:      imageRef,
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: allArtifacts,
		Summary:   generateSummary(allArtifacts, scanDuration),
		Metadata: map[string]string{
			"image_size": fmt.Sprintf("%d", imageInfo.Size),
			"layers":     fmt.Sprintf("%d", len(layers)),
		},
	}, nil
}

// ScanFilesystem scans a filesystem path for artifacts
func (m *Manager) ScanFilesystem(ctx context.Context, path string) (*artifact.Collection, error) {
	startTime := time.Now()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: path,
		Metadata: map[string]string{
			"scan_type": "filesystem",
		},
	}

	var allArtifacts []artifact.Artifact
	for _, scanner := range m.scanners {
		artifacts, err := scanner.Scan(ctx, source)
		if err != nil {
			continue
		}
		allArtifacts = append(allArtifacts, artifacts...)
	}

	// Assign unique IDs to artifacts
	allArtifacts = assignArtifactIDs(allArtifacts)

	// Analyze relationships between artifacts
	relationshipAnalyzer := NewRelationshipAnalyzer()
	allArtifacts = relationshipAnalyzer.AnalyzeRelationships(allArtifacts)

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        generateCollectionID(path),
		Name:      filepath.Base(path),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: allArtifacts,
		Summary:   generateSummary(allArtifacts, scanDuration),
		Metadata: map[string]string{
			"path": path,
		},
	}, nil
}

// scanLayer scans a single Docker layer
func (m *Manager) scanLayer(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	content, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("getting layer content: %w", err)
	}
	defer content.Close()

	var allArtifacts []artifact.Artifact

	// Run layer scanners on tar stream
	for _, scanner := range m.scanners {
		if layerScanner, ok := scanner.(LayerScanner); ok {
			freshContent, err := layer.Uncompressed()
			if err != nil {
				continue
			}

			artifacts, err := layerScanner.ScanLayer(ctx, freshContent, source)
			freshContent.Close()
			if err != nil {
				continue
			}
			allArtifacts = append(allArtifacts, artifacts...)
		}
	}

	// Extract layer and run filesystem scanners
	tempDir, err := os.MkdirTemp("", "cartographer-layer-*")
	if err != nil {
		return allArtifacts, nil
	}
	defer os.RemoveAll(tempDir)

	freshContent, err := layer.Uncompressed()
	if err != nil {
		return allArtifacts, nil
	}
	defer freshContent.Close()

	err = m.extractTarToDir(freshContent, tempDir)
	if err != nil {
		return allArtifacts, nil
	}

	tempSource := source
	tempSource.Type = artifact.SourceTypeFilesystem
	tempSource.Location = tempDir

	for _, scanner := range m.scanners {
		if _, ok := scanner.(LayerScanner); ok {
			continue
		}

		artifacts, err := scanner.Scan(ctx, tempSource)
		if err != nil {
			continue
		}

		for i := range artifacts {
			artifacts[i].Source = source
		}

		allArtifacts = append(allArtifacts, artifacts...)
	}

	return allArtifacts, nil
}

func (m *Manager) extractTarToDir(tarReader io.Reader, destDir string) error {
	tr := tar.NewReader(tarReader)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(destPath, destDir) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(destPath, os.FileMode(hdr.Mode))
			if err != nil {
				continue
			}

		case tar.TypeReg:
			err := os.MkdirAll(filepath.Dir(destPath), 0755)
			if err != nil {
				continue
			}

			file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				continue
			}

			_, err = io.Copy(file, tr)
			file.Close()
			if err != nil {
				continue
			}

		case tar.TypeSymlink:
			err := os.Symlink(hdr.Linkname, destPath)
			if err != nil {
				continue
			}
		}
	}

	return nil
}

type LayerScanner interface {
	ScanLayer(ctx context.Context, content io.Reader, source artifact.Source) ([]artifact.Artifact, error)
}

func generateCollectionID(source string) string {
	// Generate a proper unique ID based on source and timestamp
	data := fmt.Sprintf("%s:%d", source, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16] // Use first 16 chars of hash
}

func generateSummary(artifacts []artifact.Artifact, scanDuration time.Duration) artifact.Summary {
	summary := artifact.Summary{
		TotalArtifacts:  len(artifacts),
		ArtifactsByType: make(map[artifact.Type]int),
		LicenseCount:    make(map[string]int),
		ScanDuration:    scanDuration,
	}

	for _, art := range artifacts {
		summary.ArtifactsByType[art.Type]++
		for _, license := range art.Licenses {
			summary.LicenseCount[license.ID]++
		}
	}

	return summary
}

// generateArtifactID generates a unique ID for an artifact
func generateArtifactID(art *artifact.Artifact) string {
	// Create ID based on type, name, path, and source
	data := fmt.Sprintf("%s:%s:%s:%s", art.Type, art.Name, art.Path, art.Source.Location)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16] // Use first 16 chars of hash
}

// assignArtifactIDs assigns unique IDs to all artifacts
func assignArtifactIDs(artifacts []artifact.Artifact) []artifact.Artifact {
	for i := range artifacts {
		artifacts[i].ID = generateArtifactID(&artifacts[i])
	}
	return artifacts
}
