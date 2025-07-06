package scanner

import (
	"context"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/docker"
)

// PluginType represents the type of plugin to enable
type PluginType string

const (
	PluginTypeDependencyMapping PluginType = "dependency-mapping"
	PluginTypeSPDXLicense       PluginType = "spdx-license"
	PluginTypeVendorMapping     PluginType = "vendor-mapping"
	PluginTypeSecretExtraction  PluginType = "secret-extraction"
)

// ScanManager is an interface for all scan managers
type ScanManager interface {
	ScanDockerImage(ctx context.Context, imageRef string) (*artifact.Collection, error)
	ScanFilesystem(ctx context.Context, path string) (*artifact.Collection, error)
	RegisterPlugin(plugin Plugin)
	GetPluginRegistry() *PluginRegistry
}

// Ensure Manager implements ScanManager interface
var _ ScanManager = (*Manager)(nil)

// NewScanManager creates a new scanner manager with the provided scanners and plugins
// This is the main factory function that follows the pattern: scanner.NewScanManager(...scanners, ...plugins)
func NewScanManager(dockerClient *docker.Client, scanners []artifact.Scanner, plugins []Plugin) ScanManager {
	// Create manager with scanners
	manager := NewManager(dockerClient, scanners...)

	// Register plugins
	for _, plugin := range plugins {
		manager.RegisterPlugin(plugin)
	}

	return manager
}

// NewScanManagerForTypes creates a scan manager that only scans for specific artifact types
func NewScanManagerForTypes(dockerClient *docker.Client, artifactTypes []artifact.Type, enabledPlugins []PluginType) ScanManager {
	var scanners []artifact.Scanner
	var plugins []Plugin

	// Add scanners based on requested artifact types
	for _, artifactType := range artifactTypes {
		switch artifactType {
		case artifact.TypeNpmPackage, artifact.TypeYarnPackage, artifact.TypePnpmPackage:
			// Add NPM/Node.js package scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypePythonPackage, artifact.TypeCondaPackage:
			// Add Python package scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeJavaPackage, artifact.TypeMavenPackage, artifact.TypeGradlePackage:
			// Add Java package scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeGoModule:
			// Add Go module scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeRustCrate:
			// Add Rust crate scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeRubyGem:
			// Add Ruby gem scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypePHPPackage:
			// Add PHP/Composer package scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeDebianPackage, artifact.TypeRPMPackage, artifact.TypeAlpinePackage:
			// Add system package scanners
			scanners = append(scanners, NewTarLayerScanner())
		case artifact.TypeExecutable, artifact.TypeSharedLibrary, artifact.TypeStaticLibrary:
			// Add binary scanners
			scanners = append(scanners, NewTarLayerScanner())
		}
	}

	// Always include relationship analyzer for connecting artifacts
	if len(scanners) > 0 {
		scanners = append(scanners, NewRelationshipAnalyzer())
	}

	// Add plugins based on enabled list
	for _, pluginType := range enabledPlugins {
		switch pluginType {
		case PluginTypeDependencyMapping:
			// Add dependency mapping plugin when available
			// plugins = append(plugins, dependency.NewDependencyMappingPlugin())
		case PluginTypeSPDXLicense:
			// Add SPDX license mapping plugin when available
			// plugins = append(plugins, license.NewSPDXLicenseMappingPlugin())
		case PluginTypeVendorMapping:
			// Add vendor mapping plugin when available
			// plugins = append(plugins, vendor.NewVendorMappingPlugin())
		case PluginTypeSecretExtraction:
			// Add secret extraction plugin when available
			// plugins = append(plugins, security.NewSecretExtractionPlugin())
		}
	}

	return NewScanManager(dockerClient, scanners, plugins)
}
