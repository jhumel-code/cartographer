package dependency

import (
	"context"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner"
)

// DependencyMappingPlugin analyzes and maps dependencies between artifacts
type DependencyMappingPlugin struct {
	relationshipAnalyzer *scanner.RelationshipAnalyzer
}

// NewDependencyMappingPlugin creates a new dependency mapping plugin
func NewDependencyMappingPlugin() *DependencyMappingPlugin {
	return &DependencyMappingPlugin{
		relationshipAnalyzer: scanner.NewRelationshipAnalyzer(),
	}
}

// Name returns the plugin name
func (p *DependencyMappingPlugin) Name() string {
	return "dependency-mapping-plugin"
}

// Priority returns the execution priority (lower numbers execute first)
func (p *DependencyMappingPlugin) Priority() int {
	return 50 // Run after vendor mapping but before final processing
}

// SupportedTypes returns all types since dependencies can exist between any artifacts
func (p *DependencyMappingPlugin) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		// Package types
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
		// Binary types
		artifact.TypeExecutable,
		artifact.TypeSharedLibrary,
		artifact.TypeStaticLibrary,
		// Infrastructure types
		artifact.TypeDockerfile,
		artifact.TypeDockerCompose,
		artifact.TypeKubernetesManifest,
		artifact.TypeHelmChart,
	}
}

// Process analyzes and maps dependencies between artifacts
func (p *DependencyMappingPlugin) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	// Use the relationship analyzer to find dependencies
	return p.relationshipAnalyzer.AnalyzeRelationships(artifacts), nil
}
