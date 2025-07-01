package artifact

import (
	"testing"
	"time"
)

func TestArtifactCreation(t *testing.T) {
	now := time.Now()

	artifact := Artifact{
		ID:      "test-id",
		Name:    "test-package",
		Version: "1.0.0",
		Type:    TypeDebianPackage,
		Path:    "/var/lib/dpkg/info/test-package.list",
		Size:    1024,
		ModTime: &now,
		Source: Source{
			Type:     SourceTypeFilesystem,
			Location: "/test/path",
		},
		Metadata: map[string]string{
			"package_manager": "dpkg",
		},
	}

	if artifact.Name != "test-package" {
		t.Errorf("Expected name 'test-package', got '%s'", artifact.Name)
	}

	if artifact.Type != TypeDebianPackage {
		t.Errorf("Expected type '%s', got '%s'", TypeDebianPackage, artifact.Type)
	}

	if artifact.Source.Type != SourceTypeFilesystem {
		t.Errorf("Expected source type '%s', got '%s'", SourceTypeFilesystem, artifact.Source.Type)
	}
}

func TestCollectionSummary(t *testing.T) {
	artifacts := []Artifact{
		{
			Name: "package1",
			Type: TypeDebianPackage,
			Licenses: []License{
				{ID: "MIT", Name: "MIT License"},
			},
		},
		{
			Name: "package2",
			Type: TypeNpmPackage,
			Licenses: []License{
				{ID: "Apache-2.0", Name: "Apache License 2.0"},
			},
		},
	}

	collection := Collection{
		Artifacts: artifacts,
		Summary:   generateTestSummary(artifacts),
	}

	if collection.Summary.TotalArtifacts != 2 {
		t.Errorf("Expected 2 total artifacts, got %d", collection.Summary.TotalArtifacts)
	}

	if collection.Summary.ArtifactsByType[TypeDebianPackage] != 1 {
		t.Errorf("Expected 1 Debian package, got %d", collection.Summary.ArtifactsByType[TypeDebianPackage])
	}

	if collection.Summary.LicenseCount["MIT"] != 1 {
		t.Errorf("Expected 1 MIT license, got %d", collection.Summary.LicenseCount["MIT"])
	}
}

func generateTestSummary(artifacts []Artifact) Summary {
	summary := Summary{
		TotalArtifacts:  len(artifacts),
		ArtifactsByType: make(map[Type]int),
		LicenseCount:    make(map[string]int),
	}

	for _, artifact := range artifacts {
		summary.ArtifactsByType[artifact.Type]++

		for _, license := range artifact.Licenses {
			summary.LicenseCount[license.ID]++
		}
	}

	return summary
}
