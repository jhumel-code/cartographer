package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/docker"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/infrastructure"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/package_managers"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/security"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/system"
)

const ModularScannerVersion = "2.0.0-artiscanctl"

// ModularManager coordinates multiple modular scanners and plugins
type ModularManager struct {
	packageRegistry        *package_managers.Registry
	infrastructureRegistry *core.ScannerRegistry
	securityRegistry       *core.ScannerRegistry
	systemRegistry         *core.ScannerRegistry
	dockerClient           *docker.Client
	pluginRegistry         *PluginRegistry
	languages              []string // Optional language filter for package scanning
}

// NewModularManager creates a new modular scanner manager
func NewModularManager(dockerClient *docker.Client) *ModularManager {
	manager := &ModularManager{
		packageRegistry:        package_managers.NewRegistry(),
		infrastructureRegistry: core.NewScannerRegistry(),
		securityRegistry:       core.NewScannerRegistry(),
		systemRegistry:         core.NewScannerRegistry(),
		dockerClient:           dockerClient,
		pluginRegistry:         NewPluginRegistry(),
	}

	// Register infrastructure scanners
	manager.infrastructureRegistry.RegisterScanner(infrastructure.NewDockerScanner())
	manager.infrastructureRegistry.RegisterScanner(infrastructure.NewKubernetesScanner())
	manager.infrastructureRegistry.RegisterScanner(infrastructure.NewTerraformScanner())
	manager.infrastructureRegistry.RegisterScanner(infrastructure.NewAnsibleScanner())

	// Register security scanners
	manager.securityRegistry.RegisterScanner(security.NewCertificateScanner())
	manager.securityRegistry.RegisterScanner(security.NewKeyScanner())
	manager.securityRegistry.RegisterScanner(security.NewLicenseScanner())

	// Register system scanners
	manager.systemRegistry.RegisterScanner(system.NewBinaryScanner())
	manager.systemRegistry.RegisterScanner(system.NewServiceScanner())
	manager.systemRegistry.RegisterScanner(system.NewConfigScanner())

	return manager
}

// Registry access methods
func (m *ModularManager) RegisterPlugin(plugin Plugin) {
	m.pluginRegistry.Register(plugin)
}

func (m *ModularManager) GetPluginRegistry() *PluginRegistry {
	return m.pluginRegistry
}

func (m *ModularManager) GetPackageRegistry() *package_managers.Registry {
	return m.packageRegistry
}

func (m *ModularManager) GetInfrastructureRegistry() *core.ScannerRegistry {
	return m.infrastructureRegistry
}

func (m *ModularManager) GetSecurityRegistry() *core.ScannerRegistry {
	return m.securityRegistry
}

func (m *ModularManager) GetSystemRegistry() *core.ScannerRegistry {
	return m.systemRegistry
}

// ScanDockerImage scans a Docker image for artifacts using modular scanners
func (m *ModularManager) ScanDockerImage(ctx context.Context, imageRef string) (*artifact.Collection, error) {
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
	allArtifacts = m.assignModularArtifactIDs(allArtifacts)

	// Process artifacts through plugins
	enhancedArtifacts, err := m.pluginRegistry.ProcessArtifacts(ctx, allArtifacts)
	if err != nil {
		enhancedArtifacts = allArtifacts
	}

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        m.generateModularCollectionID(imageRef),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: enhancedArtifacts,
		Summary:   m.generateModularSummary(enhancedArtifacts, scanDuration),
		Metadata: map[string]string{
			"scanner_version": ModularScannerVersion,
			"scan_type":       "docker-image",
		},
	}, nil
}

// ScanFilesystem scans a filesystem path for artifacts using modular scanners
func (m *ModularManager) ScanFilesystem(ctx context.Context, path string) (*artifact.Collection, error) {
	startTime := time.Now()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: path,
		Metadata: map[string]string{
			"scan_type": "filesystem",
		},
	}

	// Scan with all scanner types
	allArtifacts := m.scanAllTypes(ctx, source)

	// Assign unique IDs and process
	allArtifacts = m.assignModularArtifactIDs(allArtifacts)
	enhancedArtifacts, err := m.pluginRegistry.ProcessArtifacts(ctx, allArtifacts)
	if err != nil {
		enhancedArtifacts = allArtifacts
	}

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        m.generateModularCollectionID(path),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: enhancedArtifacts,
		Summary:   m.generateModularSummary(enhancedArtifacts, scanDuration),
		Metadata: map[string]string{
			"scanner_version": ModularScannerVersion,
			"scan_type":       "filesystem",
		},
	}, nil
}

// scanAllTypes scans with all registered scanner types
func (m *ModularManager) scanAllTypes(ctx context.Context, source artifact.Source) []artifact.Artifact {
	var allArtifacts []artifact.Artifact

	// Scan with package scanners
	packageArtifacts := m.scanPackages(ctx, source)
	allArtifacts = append(allArtifacts, packageArtifacts...)

	// Scan with other scanner types
	if infraArtifacts, err := m.infrastructureRegistry.ScanWithAllScanners(ctx, source); err == nil {
		allArtifacts = append(allArtifacts, infraArtifacts...)
	}

	if securityArtifacts, err := m.securityRegistry.ScanWithAllScanners(ctx, source); err == nil {
		allArtifacts = append(allArtifacts, securityArtifacts...)
	}

	if systemArtifacts, err := m.systemRegistry.ScanWithAllScanners(ctx, source); err == nil {
		allArtifacts = append(allArtifacts, systemArtifacts...)
	}

	return allArtifacts
}

// scanPackages scans with package managers (language-filtered if specified)
func (m *ModularManager) scanPackages(ctx context.Context, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	if m.languages != nil && len(m.languages) > 0 {
		// Use language-specific filtering
		for _, language := range m.languages {
			scanners := m.packageRegistry.GetLanguageSpecificScanners(language)
			for _, scanner := range scanners {
				if langArtifacts, err := scanner.Scan(ctx, source); err == nil {
					artifacts = append(artifacts, langArtifacts...)
				}
			}
		}
	} else {
		// Use all package scanners
		if packageArtifacts, err := m.packageRegistry.ScanWithAllScanners(ctx, source); err == nil {
			artifacts = append(artifacts, packageArtifacts...)
		}
	}

	return artifacts
}

// ScanWithLanguageFilter scans using only package managers for specific languages
func (m *ModularManager) ScanWithLanguageFilter(ctx context.Context, source artifact.Source, languages []string) (*artifact.Collection, error) {
	startTime := time.Now()

	var allArtifacts []artifact.Artifact

	for _, language := range languages {
		scanners := m.packageRegistry.GetLanguageSpecificScanners(language)
		for _, scanner := range scanners {
			if artifacts, err := scanner.Scan(ctx, source); err == nil {
				allArtifacts = append(allArtifacts, artifacts...)
			}
		}
	}

	allArtifacts = m.assignModularArtifactIDs(allArtifacts)
	enhancedArtifacts, err := m.pluginRegistry.ProcessArtifacts(ctx, allArtifacts)
	if err != nil {
		enhancedArtifacts = allArtifacts
	}

	scanDuration := time.Since(startTime)

	return &artifact.Collection{
		ID:        m.generateModularCollectionID(source.Location),
		Source:    source,
		ScanTime:  time.Now(),
		Artifacts: enhancedArtifacts,
		Summary:   m.generateModularSummary(enhancedArtifacts, scanDuration),
		Metadata: map[string]string{
			"scanner_version": ModularScannerVersion,
			"scan_type":       "language-filtered",
			"languages":       fmt.Sprintf("%v", languages),
		},
	}, nil
}

// Helper methods
func (m *ModularManager) scanLayer(ctx context.Context, layer v1.Layer, source artifact.Source) ([]artifact.Artifact, error) {
	layerScanner := NewTarLayerScanner()
	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return layerScanner.ScanLayer(ctx, reader, source)
}

func (m *ModularManager) generateModularCollectionID(source string) string {
	data := fmt.Sprintf("%s:%d", source, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

func (m *ModularManager) generateModularSummary(artifacts []artifact.Artifact, scanDuration time.Duration) artifact.Summary {
	summary := artifact.Summary{
		TotalArtifacts:  len(artifacts),
		ArtifactsByType: make(map[artifact.Type]int),
		LicenseCount:    make(map[string]int),
		ScanDuration:    artifact.Duration{Duration: scanDuration},
	}

	for _, art := range artifacts {
		summary.ArtifactsByType[art.Type]++
		for _, license := range art.Licenses {
			summary.LicenseCount[license.Name]++
		}
	}

	return summary
}

func (m *ModularManager) assignModularArtifactIDs(artifacts []artifact.Artifact) []artifact.Artifact {
	for i := range artifacts {
		artifacts[i].ID = m.generateModularArtifactID(artifacts[i])
	}
	return artifacts
}

func (m *ModularManager) generateModularArtifactID(art artifact.Artifact) string {
	data := fmt.Sprintf("%s:%s:%s:%s", art.Name, art.Version, art.Type, art.Path)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:12]
}
