package plugins

import (
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/dependency"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/license"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/publishers"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/security"
)

// PluginRegistry provides access to all modular plugins
type PluginRegistry struct{}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{}
}

// GetVendorMappingPlugin returns a new vendor mapping plugin
func (r *PluginRegistry) GetVendorMappingPlugin() *publishers.VendorMappingPlugin {
	return publishers.NewVendorMappingPlugin()
}

// GetSPDXLicenseMappingPlugin returns a new SPDX license mapping plugin
func (r *PluginRegistry) GetSPDXLicenseMappingPlugin() *license.SPDXLicenseMappingPlugin {
	return license.NewSPDXLicenseMappingPlugin()
}

// GetSecretExtractionPlugin returns a new secret extraction plugin
func (r *PluginRegistry) GetSecretExtractionPlugin() *security.SecretExtractionPlugin {
	return security.NewSecretExtractionPlugin()
}

// GetDependencyMappingPlugin returns a new dependency mapping plugin
func (r *PluginRegistry) GetDependencyMappingPlugin() *dependency.DependencyMappingPlugin {
	return dependency.NewDependencyMappingPlugin()
}

// GetAllPlugins returns all available plugins
func (r *PluginRegistry) GetAllPlugins() []interface{} {
	return []interface{}{
		r.GetVendorMappingPlugin(),
		r.GetSPDXLicenseMappingPlugin(),
		r.GetSecretExtractionPlugin(),
		r.GetDependencyMappingPlugin(),
	}
}

// GetDefaultPlugins returns the default set of plugins for most use cases
func (r *PluginRegistry) GetDefaultPlugins() []interface{} {
	return []interface{}{
		r.GetVendorMappingPlugin(),
		r.GetSPDXLicenseMappingPlugin(),
		r.GetSecretExtractionPlugin(),
		r.GetDependencyMappingPlugin(),
	}
}

// GetLightweightPlugins returns a minimal set of plugins for basic scanning
func (r *PluginRegistry) GetLightweightPlugins() []interface{} {
	return []interface{}{
		r.GetVendorMappingPlugin(),
	}
}
