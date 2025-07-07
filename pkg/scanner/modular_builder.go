package scanner

import (
	"github.com/jhumel-code/artiscanctl/pkg/docker"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/package_managers"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/license"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/publishers"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/security"
)

// NewModularDefaultManager creates a modular manager with all default scanners and plugins
func NewModularDefaultManager(dockerClient *docker.Client) *ModularManager {
	manager := NewModularManager(dockerClient)

	// Register plugins in priority order using modular plugins
	manager.RegisterPlugin(publishers.NewVendorMappingPlugin())   // Priority 10
	manager.RegisterPlugin(license.NewSPDXLicenseMappingPlugin()) // Priority 20
	manager.RegisterPlugin(security.NewSecretExtractionPlugin())  // Priority 30
	// TODO: Fix import cycle for dependency plugin
	// manager.RegisterPlugin(dependency.NewDependencyMappingPlugin())  // Priority 50

	return manager
}

// NewModularPackageOnlyManager creates a modular manager focused on package detection
func NewModularPackageOnlyManager(dockerClient *docker.Client) *ModularManager {
	manager := &ModularManager{
		packageRegistry:        package_managers.NewRegistry(),
		infrastructureRegistry: core.NewScannerRegistry(), // Empty but not nil
		securityRegistry:       core.NewScannerRegistry(), // Empty but not nil
		systemRegistry:         core.NewScannerRegistry(), // Empty but not nil
		dockerClient:           dockerClient,
		pluginRegistry:         NewPluginRegistry(),
	}

	// Register package enhancement plugins
	manager.RegisterPlugin(publishers.NewVendorMappingPlugin())
	// TODO: Fix import cycle for dependency plugin
	// manager.RegisterPlugin(dependency.NewDependencyMappingPlugin())

	return manager
}

// NewModularLanguageSpecificManager creates a manager for specific programming languages
func NewModularLanguageSpecificManager(dockerClient *docker.Client, languages []string) *ModularManager {
	manager := &ModularManager{
		packageRegistry:        package_managers.NewRegistry(),
		infrastructureRegistry: core.NewScannerRegistry(), // Empty but not nil
		securityRegistry:       core.NewScannerRegistry(), // Empty but not nil
		systemRegistry:         core.NewScannerRegistry(), // Empty but not nil
		dockerClient:           dockerClient,
		pluginRegistry:         NewPluginRegistry(),
		languages:              languages, // Store the languages for filtering
	}

	// Register language-specific plugins
	manager.RegisterPlugin(publishers.NewVendorMappingPlugin())
	// TODO: Fix import cycle for dependency plugin
	// manager.RegisterPlugin(dependency.NewDependencyMappingPlugin())

	return manager
}

// NewModularSecurityFocusedManager creates a modular manager focused on security artifacts
func NewModularSecurityFocusedManager(dockerClient *docker.Client) *ModularManager {
	manager := NewModularManager(dockerClient)

	// Register security-focused plugins
	manager.RegisterPlugin(security.NewSecretExtractionPlugin())
	manager.RegisterPlugin(license.NewSPDXLicenseMappingPlugin())
	manager.RegisterPlugin(publishers.NewVendorMappingPlugin())

	return manager
}

// NewModularInfrastructureOnlyManager creates a manager focused on infrastructure analysis
func NewModularInfrastructureOnlyManager(dockerClient *docker.Client) *ModularManager {
	manager := &ModularManager{
		packageRegistry:        &package_managers.Registry{ScannerRegistry: core.NewScannerRegistry()}, // Empty but not nil
		infrastructureRegistry: NewModularManager(dockerClient).GetInfrastructureRegistry(),
		securityRegistry:       core.NewScannerRegistry(), // Empty but not nil
		systemRegistry:         core.NewScannerRegistry(), // Empty but not nil
		dockerClient:           dockerClient,
		pluginRegistry:         NewPluginRegistry(),
	}

	return manager
}

// NewModularCustomManager creates a manager with custom scanner selection
func NewModularCustomManager(dockerClient *docker.Client, config ModularManagerConfig) *ModularManager {
	manager := NewModularManager(dockerClient)

	// Configure based on provided config
	if !config.EnablePackageScanning {
		// Remove package registry
		manager.packageRegistry = nil
	}

	if !config.EnableInfrastructureScanning {
		// Remove infrastructure registry
		manager.infrastructureRegistry = nil
	}

	if !config.EnableSecurityScanning {
		// Remove security registry
		manager.securityRegistry = nil
	}

	if !config.EnableSystemScanning {
		// Remove system registry
		manager.systemRegistry = nil
	}

	// Register custom plugins
	for _, plugin := range config.CustomPlugins {
		manager.RegisterPlugin(plugin)
	}

	return manager
}

// ModularManagerConfig defines configuration for custom manager creation
type ModularManagerConfig struct {
	EnablePackageScanning        bool
	EnableInfrastructureScanning bool
	EnableSecurityScanning       bool
	EnableSystemScanning         bool
	Languages                    []string
	CustomPlugins                []Plugin
}

// DefaultModularManagerConfig returns a default configuration
func DefaultModularManagerConfig() ModularManagerConfig {
	return ModularManagerConfig{
		EnablePackageScanning:        true,
		EnableInfrastructureScanning: true,
		EnableSecurityScanning:       true,
		EnableSystemScanning:         true,
		Languages:                    []string{},
		CustomPlugins:                []Plugin{},
	}
}
