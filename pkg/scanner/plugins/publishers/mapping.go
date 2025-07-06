package publishers

import (
	"context"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// VendorMappingPlugin enhances package artifacts with vendor information
type VendorMappingPlugin struct {
	vendorMapper *VendorMapper
}

// NewVendorMappingPlugin creates a new vendor mapping plugin
func NewVendorMappingPlugin() *VendorMappingPlugin {
	return &VendorMappingPlugin{
		vendorMapper: NewVendorMapper(),
	}
}

// Name returns the plugin name
func (p *VendorMappingPlugin) Name() string {
	return "vendor-mapping-plugin"
}

// Priority returns the execution priority (lower numbers execute first)
func (p *VendorMappingPlugin) Priority() int {
	return 10 // Run early to add vendor info
}

// SupportedTypes returns the package types this plugin can enhance
func (p *VendorMappingPlugin) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeNpmPackage,
		artifact.TypeYarnPackage,
		artifact.TypePnpmPackage,
		artifact.TypePythonPackage,
		artifact.TypeCondaPackage,
		artifact.TypeJavaPackage,
		artifact.TypeMavenPackage,
		artifact.TypeGradlePackage,
		artifact.TypeGoModule,
		artifact.TypeRustCrate,
		artifact.TypeRubyGem,
		artifact.TypePHPPackage,
		artifact.TypeDotNetPackage,
		artifact.TypeHaskellPackage,
		artifact.TypeSwiftPackage,
		artifact.TypeDartPackage,
		artifact.TypeCocoaPod,
		artifact.TypeCarthagePackage,
		artifact.TypeConanPackage,
		artifact.TypeVcpkgPackage,
		artifact.TypeCRANPackage,
		artifact.TypeHexPackage,
		artifact.TypeDebianPackage,
		artifact.TypeRPMPackage,
		artifact.TypeAlpinePackage,
		artifact.TypeArchPackage,
		artifact.TypeGentooPackage,
		artifact.TypeSnapPackage,
		artifact.TypeFlatpakPackage,
		artifact.TypeAppImagePackage,
	}
}

// Process enhances artifacts with vendor information
func (p *VendorMappingPlugin) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	enhancedArtifacts := make([]artifact.Artifact, 0, len(artifacts))

	for _, art := range artifacts {
		enhanced := art

		// Get vendor information for the artifact
		vendorInfo := p.vendorMapper.GetVendorInfo(&art)

		// Add vendor metadata
		if enhanced.Metadata == nil {
			enhanced.Metadata = make(map[string]string)
		}

		if vendorInfo.Vendor != "" {
			enhanced.Metadata["vendor"] = vendorInfo.Vendor
		}
		if vendorInfo.Publisher != "" {
			enhanced.Metadata["publisher"] = vendorInfo.Publisher
		}
		if vendorInfo.Ecosystem != "" {
			enhanced.Metadata["ecosystem"] = vendorInfo.Ecosystem
		}
		if vendorInfo.Distribution != "" {
			enhanced.Metadata["distribution"] = vendorInfo.Distribution
		}
		if vendorInfo.SourceURL != "" {
			enhanced.Metadata["source_url"] = vendorInfo.SourceURL
		}
		if vendorInfo.RepositoryURL != "" {
			enhanced.Metadata["repository_url"] = vendorInfo.RepositoryURL
		}

		enhancedArtifacts = append(enhancedArtifacts, enhanced)
	}

	return enhancedArtifacts, nil
}
