package scanner

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// RelationshipAnalyzer builds relationships between artifacts
type RelationshipAnalyzer struct{}

// NewRelationshipAnalyzer creates a new relationship analyzer
func NewRelationshipAnalyzer() *RelationshipAnalyzer {
	return &RelationshipAnalyzer{}
}

func (r *RelationshipAnalyzer) Name() string {
	return "relationship-analyzer"
}

func (r *RelationshipAnalyzer) SupportedTypes() []artifact.Type {
	// This analyzer doesn't create new artifacts, it enhances existing ones
	return []artifact.Type{}
}

func (r *RelationshipAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	// This analyzer is used post-processing to analyze relationships
	// It doesn't return new artifacts but enhances existing ones
	return []artifact.Artifact{}, nil
}

// AnalyzeRelationships analyzes and establishes relationships between artifacts
func (r *RelationshipAnalyzer) AnalyzeRelationships(artifacts []artifact.Artifact) []artifact.Artifact {
	// Create maps for efficient lookup
	artifactsByName := make(map[string]*artifact.Artifact)
	artifactsByPath := make(map[string]*artifact.Artifact)
	artifactsByType := make(map[artifact.Type][]*artifact.Artifact)

	// Index artifacts for relationship analysis
	for i := range artifacts {
		art := &artifacts[i]
		artifactsByName[art.Name] = art
		artifactsByPath[art.Path] = art
		artifactsByType[art.Type] = append(artifactsByType[art.Type], art)
	}

	// Analyze relationships for each artifact
	for i := range artifacts {
		art := &artifacts[i]
		r.buildRelationshipsForArtifact(art, artifactsByName, artifactsByPath, artifactsByType)
	}

	return artifacts
}

func (r *RelationshipAnalyzer) buildRelationshipsForArtifact(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	if art.Relationships == nil {
		art.Relationships = []artifact.Relationship{}
	}

	// Analyze type-specific relationships
	r.analyzeTypeSpecificRelationships(art, artifactsByName, artifactsByPath, artifactsByType)

	// Analyze common relationships
	r.analyzeDependencyRelationships(art, artifactsByName)
	r.analyzeContainmentRelationships(art, artifactsByPath)
	r.analyzeConfigurationRelationships(art, artifactsByName, artifactsByPath)
}

func (r *RelationshipAnalyzer) analyzeTypeSpecificRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	switch art.Type {
	case artifact.TypeDockerfile:
		r.analyzeContainerRelationships(art, artifactsByPath, artifact.RelationshipBuilds, "container-orchestration")
	case artifact.TypeDockerCompose:
		r.analyzeContainerRelationships(art, artifactsByPath, artifact.RelationshipDependsOn, "build-dependency")
	case artifact.TypeKubernetesManifest:
		r.analyzeKubernetesRelationships(art, artifactsByPath)
	case artifact.TypeTerraformConfig:
		r.analyzeTerraformRelationships(art, artifactsByPath)
	case artifact.TypeJenkinsfile, artifact.TypeGitHubActions, artifact.TypeGitLabCI:
		r.analyzeCIRelationships(art, artifactsByPath)
	case artifact.TypeExecutable:
		r.analyzeExecutableRelationships(art, artifactsByType)
	case artifact.TypeSharedLibrary:
		r.analyzeLibraryRelationships(art, artifactsByType)
	}
}

func (r *RelationshipAnalyzer) analyzeContainerRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
	relType artifact.RelationshipType,
	relMetadata string,
) {
	dir := filepath.Dir(art.Path)
	targetType := artifact.TypeDockerfile
	if art.Type == artifact.TypeDockerfile {
		targetType = artifact.TypeDockerCompose
	}

	r.addDirectoryBasedRelationships(art, artifactsByPath, dir, []artifact.Type{targetType}, relType, relMetadata)
}

func (r *RelationshipAnalyzer) analyzeKubernetesRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	dir := filepath.Dir(art.Path)
	targetTypes := []artifact.Type{artifact.TypeDockerfile, artifact.TypeDockerCompose}
	r.addDirectoryBasedRelationships(art, artifactsByPath, dir, targetTypes, artifact.RelationshipDependsOn, "container-dependency")
}

func (r *RelationshipAnalyzer) analyzeTerraformRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	tfDir := filepath.Dir(art.Path)

	for path, target := range artifactsByPath {
		if target.Type == artifact.TypeTerraformConfig &&
			target.Path != art.Path &&
			strings.HasPrefix(path, tfDir) {
			r.addRelationship(art, target, artifact.RelationshipRequires, "terraform-module")
		}
	}
}

func (r *RelationshipAnalyzer) analyzeCIRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	dir := filepath.Dir(art.Path)
	targetTypes := []artifact.Type{artifact.TypeDockerfile, artifact.TypeMakefile, artifact.TypeBuildScript}
	r.addDirectoryBasedRelationships(art, artifactsByPath, dir, targetTypes, artifact.RelationshipBuilds, "ci-build")
}

func (r *RelationshipAnalyzer) analyzeExecutableRelationships(
	art *artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	for _, lib := range artifactsByType[artifact.TypeSharedLibrary] {
		libBaseName := strings.TrimSuffix(lib.Name, filepath.Ext(lib.Name))
		if strings.Contains(art.Path, libBaseName) || r.isCommonLibrary(lib.Name) {
			r.addRelationship(art, lib, artifact.RelationshipLinks, "dynamic-linking")
		}
	}
}

func (r *RelationshipAnalyzer) analyzeLibraryRelationships(
	art *artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	for _, lib := range artifactsByType[artifact.TypeSharedLibrary] {
		if lib.Path != art.Path && r.isRelatedLibrary(art.Name, lib.Name) {
			r.addRelationship(art, lib, artifact.RelationshipDependsOn, "library-dependency")
		}
	}
}

func (r *RelationshipAnalyzer) analyzeDependencyRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
) {
	for _, depName := range art.Dependencies {
		if target, exists := artifactsByName[depName]; exists {
			r.addRelationship(art, target, artifact.RelationshipDependsOn, "package-dependency")
		}
	}
}

func (r *RelationshipAnalyzer) analyzeContainmentRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	artDir := filepath.Dir(art.Path)

	for path, target := range artifactsByPath {
		if target.Path != art.Path && strings.HasPrefix(path, artDir+"/") {
			r.addRelationship(art, target, artifact.RelationshipContains, "directory-containment")
		}
	}
}

func (r *RelationshipAnalyzer) analyzeConfigurationRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	if art.Type != artifact.TypeConfigFile {
		return
	}

	dir := filepath.Dir(art.Path)
	targetTypes := []artifact.Type{artifact.TypeExecutable, artifact.TypeSystemdService}
	r.addDirectoryBasedRelationships(art, artifactsByPath, dir, targetTypes, artifact.RelationshipConfigures, "service-configuration")
}

// Helper methods
func (r *RelationshipAnalyzer) addDirectoryBasedRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
	dir string,
	targetTypes []artifact.Type,
	relType artifact.RelationshipType,
	relMetadata string,
) {
	for path, target := range artifactsByPath {
		if r.matchesTargetType(target.Type, targetTypes) && strings.HasPrefix(path, dir) {
			r.addRelationship(art, target, relType, relMetadata)
		}
	}
}

func (r *RelationshipAnalyzer) matchesTargetType(artType artifact.Type, targetTypes []artifact.Type) bool {
	for _, targetType := range targetTypes {
		if artType == targetType {
			return true
		}
	}
	return false
}

func (r *RelationshipAnalyzer) addRelationship(
	art *artifact.Artifact,
	target *artifact.Artifact,
	relType artifact.RelationshipType,
	relMetadata string,
) {
	art.Relationships = append(art.Relationships, artifact.Relationship{
		Type:       relType,
		TargetID:   target.ID,
		TargetName: target.Name,
		Metadata: map[string]string{
			"relationship_type": relMetadata,
		},
	})
}

func (r *RelationshipAnalyzer) isCommonLibrary(libName string) bool {
	commonLibs := []string{
		"libc.so", "libm.so", "libpthread.so", "libdl.so", "librt.so",
		"libssl.so", "libcrypto.so", "libz.so", "libxml2.so", "libcurl.so",
	}

	for _, common := range commonLibs {
		if strings.Contains(libName, common) {
			return true
		}
	}
	return false
}

func (r *RelationshipAnalyzer) isRelatedLibrary(lib1, lib2 string) bool {
	base1 := strings.TrimSuffix(lib1, filepath.Ext(lib1))
	base2 := strings.TrimSuffix(lib2, filepath.Ext(lib2))

	// Remove version numbers and common prefixes
	base1 = strings.TrimPrefix(base1, "lib")
	base2 = strings.TrimPrefix(base2, "lib")

	// Check if one is a substring of the other (indicating related libraries)
	return strings.Contains(base1, base2) || strings.Contains(base2, base1)
}
