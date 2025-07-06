package scanner

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/docker"
)

// Manager coordinates multiple scanners and plugins to analyze sources
type Manager struct {
	scanners       []artifact.Scanner
	dockerClient   *docker.Client
	pluginRegistry *PluginRegistry
}

// NewManager creates a new scanner manager
func NewManager(dockerClient *docker.Client, scanners ...artifact.Scanner) *Manager {
	manager := &Manager{
		scanners:       make([]artifact.Scanner, 0),
		dockerClient:   dockerClient,
		pluginRegistry: NewPluginRegistry(),
	}

	// Register listed scanners
	for _, scanner := range scanners {
		manager.RegisterScanner(scanner)
	}

	return manager
}

// RegisterScanner adds a scanner to the manager
func (m *Manager) RegisterScanner(scanner artifact.Scanner) {
	m.scanners = append(m.scanners, scanner)
}

// RegisterPlugin adds a plugin to the manager
func (m *Manager) RegisterPlugin(plugin Plugin) {
	m.pluginRegistry.Register(plugin)
}

// GetPluginRegistry returns the plugin registry for advanced operations
func (m *Manager) GetPluginRegistry() *PluginRegistry {
	return m.pluginRegistry
}

// ScanDockerImage scans a Docker image for artifacts
func (m *Manager) ScanDockerImage(ctx context.Context, imageRef string) (*artifact.Collection, error) {
	scanner := NewDockerImageScanner(m.dockerClient, m.scanners, m.pluginRegistry)
	return scanner.Scan(ctx, imageRef)
}

// ScanFilesystem scans a filesystem path for artifacts
func (m *Manager) ScanFilesystem(ctx context.Context, path string) (*artifact.Collection, error) {
	scanner := NewFilesystemScanner(m.scanners, m.pluginRegistry)
	return scanner.Scan(ctx, path)
}

// scanLayer scans a single Docker layer
func (m *Manager) scanLayer(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	var allArtifacts []artifact.Artifact

	// Run layer scanners on tar stream
	layerArtifacts, err := m.runLayerScanners(ctx, layer, source)
	if err != nil {
		return nil, fmt.Errorf("running layer scanners: %w", err)
	}
	allArtifacts = append(allArtifacts, layerArtifacts...)

	// Extract layer and run filesystem scanners
	filesystemArtifacts, err := m.runFilesystemScannersOnLayer(ctx, layer, source)
	if err != nil {
		// Continue with layer artifacts even if filesystem scanning fails
		return allArtifacts, nil
	}
	allArtifacts = append(allArtifacts, filesystemArtifacts...)

	return allArtifacts, nil
}

func (m *Manager) runLayerScanners(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	for _, scanner := range m.scanners {
		if layerScanner, ok := scanner.(LayerScanner); ok {
			scannerArtifacts, err := m.runSingleLayerScanner(ctx, layer, source, layerScanner)
			if err != nil {
				continue // Skip failed scanners
			}
			artifacts = append(artifacts, scannerArtifacts...)
		}
	}

	return artifacts, nil
}

func (m *Manager) runSingleLayerScanner(ctx context.Context, layer v1.Layer, source artifact.Source, scanner LayerScanner) ([]artifact.Artifact, error) {
	content, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer content.Close()

	return scanner.ScanLayer(ctx, content, source)
}

func (m *Manager) runFilesystemScannersOnLayer(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	tempDir, err := m.extractLayerToTempDir(layer)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	tempSource := source
	tempSource.Type = artifact.SourceTypeFilesystem
	tempSource.Location = tempDir

	return m.runFilesystemScanners(ctx, tempSource, source)
}

func (m *Manager) extractLayerToTempDir(layer v1.Layer) (string, error) {
	tempDir, err := os.MkdirTemp("", "cartographer-layer-*")
	if err != nil {
		return "", err
	}

	content, err := layer.Uncompressed()
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}
	defer content.Close()

	err = m.extractTarToDir(content, tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}

	return tempDir, nil
}

func (m *Manager) runFilesystemScanners(ctx context.Context, tempSource, originalSource artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	for _, scanner := range m.scanners {
		if _, ok := scanner.(LayerScanner); ok {
			continue // Skip layer scanners
		}

		scannerArtifacts, err := scanner.Scan(ctx, tempSource)
		if err != nil {
			continue // Skip failed scanners
		}

		// Update source back to original
		for i := range scannerArtifacts {
			scannerArtifacts[i].Source = originalSource
		}

		artifacts = append(artifacts, scannerArtifacts...)
	}

	return artifacts, nil
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

		if err := m.extractTarEntry(tr, hdr, destDir); err != nil {
			continue // Skip problematic entries
		}
	}

	return nil
}

func (m *Manager) extractTarEntry(tr *tar.Reader, hdr *tar.Header, destDir string) error {
	destPath := filepath.Join(destDir, hdr.Name)
	if !strings.HasPrefix(destPath, destDir) {
		return fmt.Errorf("path traversal detected: %s", hdr.Name)
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		return m.extractDirectory(destPath, hdr)
	case tar.TypeReg:
		return m.extractRegularFile(tr, destPath, hdr)
	case tar.TypeSymlink:
		return m.extractSymlink(destPath, hdr)
	default:
		return fmt.Errorf("unsupported tar entry type: %c", hdr.Typeflag)
	}
}

func (m *Manager) extractDirectory(destPath string, hdr *tar.Header) error {
	return os.MkdirAll(destPath, os.FileMode(hdr.Mode))
}

func (m *Manager) extractRegularFile(tr *tar.Reader, destPath string, hdr *tar.Header) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, tr)
	return err
}

func (m *Manager) extractSymlink(destPath string, hdr *tar.Header) error {
	return os.Symlink(hdr.Linkname, destPath)
}
