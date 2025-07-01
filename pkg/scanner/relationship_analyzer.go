package scanner

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
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

	switch art.Type {
	case artifact.TypeDockerfile:
		r.analyzeDockerfileRelationships(art, artifactsByName, artifactsByPath)
	case artifact.TypeDockerCompose:
		r.analyzeDockerComposeRelationships(art, artifactsByName, artifactsByPath)
	case artifact.TypeKubernetesManifest:
		r.analyzeKubernetesRelationships(art, artifactsByName, artifactsByPath)
	case artifact.TypeTerraformConfig:
		r.analyzeTerraformRelationships(art, artifactsByName, artifactsByPath)
	case artifact.TypeJenkinsfile, artifact.TypeGitHubActions, artifact.TypeGitLabCI:
		r.analyzeCIRelationships(art, artifactsByName, artifactsByPath)
	case artifact.TypeExecutable:
		r.analyzeExecutableRelationships(art, artifactsByName, artifactsByType)
	case artifact.TypeSharedLibrary:
		r.analyzeLibraryRelationships(art, artifactsByName, artifactsByType)
	}

	// Analyze dependency relationships
	r.analyzeDependencyRelationships(art, artifactsByName)

	// Analyze containment relationships
	r.analyzeContainmentRelationships(art, artifactsByPath)

	// Analyze configuration relationships
	r.analyzeConfigurationRelationships(art, artifactsByName, artifactsByPath)
}

func (r *RelationshipAnalyzer) analyzeDockerfileRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	// Dockerfile typically builds container images
	dockerDir := filepath.Dir(art.Path)

	// Look for related Docker Compose files
	for path, target := range artifactsByPath {
		if target.Type == artifact.TypeDockerCompose &&
			strings.HasPrefix(path, dockerDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipBuilds,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "container-orchestration",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeDockerComposeRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	composeDir := filepath.Dir(art.Path)

	// Look for Dockerfiles in the same directory
	for path, target := range artifactsByPath {
		if target.Type == artifact.TypeDockerfile &&
			strings.HasPrefix(path, composeDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipDependsOn,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "build-dependency",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeKubernetesRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	// Kubernetes manifests often depend on container images
	// This would require parsing the YAML content to find image references
	// For now, establish directory-based relationships
	k8sDir := filepath.Dir(art.Path)

	for path, target := range artifactsByPath {
		if (target.Type == artifact.TypeDockerfile || target.Type == artifact.TypeDockerCompose) &&
			strings.HasPrefix(path, k8sDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipDependsOn,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "container-dependency",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeTerraformRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	tfDir := filepath.Dir(art.Path)

	// Terraform files in the same directory often work together
	for path, target := range artifactsByPath {
		if target.Type == artifact.TypeTerraformConfig &&
			target.Path != art.Path &&
			strings.HasPrefix(path, tfDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipRequires,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "terraform-module",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeCIRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	ciDir := filepath.Dir(art.Path)

	// CI files often build and deploy other artifacts
	for path, target := range artifactsByPath {
		if (target.Type == artifact.TypeDockerfile ||
			target.Type == artifact.TypeMakefile ||
			target.Type == artifact.TypeBuildScript) &&
			strings.HasPrefix(path, ciDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipBuilds,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "ci-build",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeExecutableRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	// Executables often link to shared libraries
	for _, lib := range artifactsByType[artifact.TypeSharedLibrary] {
		// Simple heuristic: if library name appears in executable path or is common
		libBaseName := strings.TrimSuffix(lib.Name, filepath.Ext(lib.Name))
		if strings.Contains(art.Path, libBaseName) || r.isCommonLibrary(lib.Name) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipLinks,
				TargetID:   lib.ID,
				TargetName: lib.Name,
				Metadata: map[string]string{
					"relationship_type": "dynamic-linking",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeLibraryRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
	artifactsByType map[artifact.Type][]*artifact.Artifact,
) {
	// Libraries can depend on other libraries
	for _, lib := range artifactsByType[artifact.TypeSharedLibrary] {
		if lib.Path != art.Path && r.isRelatedLibrary(art.Name, lib.Name) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipDependsOn,
				TargetID:   lib.ID,
				TargetName: lib.Name,
				Metadata: map[string]string{
					"relationship_type": "library-dependency",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeDependencyRelationships(
	art *artifact.Artifact,
	artifactsByName map[string]*artifact.Artifact,
) {
	// Use existing Dependencies field to create formal relationships
	for _, depName := range art.Dependencies {
		if target, exists := artifactsByName[depName]; exists {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipDependsOn,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "package-dependency",
				},
			})
		}
	}
}

func (r *RelationshipAnalyzer) analyzeContainmentRelationships(
	art *artifact.Artifact,
	artifactsByPath map[string]*artifact.Artifact,
) {
	artDir := filepath.Dir(art.Path)

	// Find artifacts contained within this artifact's directory
	for path, target := range artifactsByPath {
		if target.Path != art.Path && strings.HasPrefix(path, artDir+"/") {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipContains,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "directory-containment",
				},
			})
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

	configDir := filepath.Dir(art.Path)

	// Configuration files often configure executables or services
	for path, target := range artifactsByPath {
		if (target.Type == artifact.TypeExecutable ||
			target.Type == artifact.TypeSystemdService) &&
			strings.HasPrefix(path, configDir) {
			art.Relationships = append(art.Relationships, artifact.Relationship{
				Type:       artifact.RelationshipConfigures,
				TargetID:   target.ID,
				TargetName: target.Name,
				Metadata: map[string]string{
					"relationship_type": "service-configuration",
				},
			})
		}
	}
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
	// Simple heuristic: libraries with similar names might be related
	base1 := strings.TrimSuffix(lib1, filepath.Ext(lib1))
	base2 := strings.TrimSuffix(lib2, filepath.Ext(lib2))

	// Remove version numbers and common prefixes
	base1 = strings.TrimPrefix(base1, "lib")
	base2 = strings.TrimPrefix(base2, "lib")

	// Check if one is a substring of the other (indicating related libraries)
	return strings.Contains(base1, base2) || strings.Contains(base2, base1)
}
