package package_managers

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

const (
	PomXMLFile = "pom.xml"
)

// MavenScanner scans for Maven dependencies
type MavenScanner struct {
	*core.BaseScanner
}

// NewMavenScanner creates a new Maven scanner
func NewMavenScanner() *MavenScanner {
	patterns := []string{
		PomXMLFile,
	}

	supportedTypes := []artifact.Type{
		artifact.TypeMavenPackage,
	}

	return &MavenScanner{
		BaseScanner: core.NewBaseScanner("maven-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Maven packages in the source
func (m *MavenScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return m.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !m.MatchesFile(filename, path) {
			return nil, nil
		}

		if filename == PomXMLFile {
			return m.parsePomXML(path, source)
		}

		return nil, nil
	})
}

// POM XML structure for parsing
type POM struct {
	XMLName      xml.Name `xml:"project"`
	GroupID      string   `xml:"groupId"`
	ArtifactID   string   `xml:"artifactId"`
	Version      string   `xml:"version"`
	Packaging    string   `xml:"packaging"`
	Dependencies struct {
		Dependency []Dependency `xml:"dependency"`
	} `xml:"dependencies"`
	Properties map[string]string `xml:"properties"`
}

type Dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   bool   `xml:"optional"`
}

// parsePomXML parses a pom.xml file
func (m *MavenScanner) parsePomXML(path string, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts, err
	}
	defer file.Close()

	var pom POM
	if err := xml.NewDecoder(file).Decode(&pom); err != nil {
		return artifacts, err
	}

	// Create artifact for the main project
	if pom.ArtifactID != "" {
		metadata := map[string]string{
			"package_manager": "maven",
			"source_file":     PomXMLFile,
			"group_id":        pom.GroupID,
			"packaging":       pom.Packaging,
		}

		mainArtifact := m.CreateArtifact(
			pom.ArtifactID,
			pom.Version,
			artifact.TypeMavenPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, mainArtifact)
	}

	// Parse dependencies
	for _, dep := range pom.Dependencies.Dependency {
		depType := "compile"
		if dep.Scope != "" {
			depType = dep.Scope
		}

		metadata := map[string]string{
			"package_manager": "maven",
			"source_file":     PomXMLFile,
			"group_id":        dep.GroupID,
			"dependency_type": depType,
			"optional":        "false",
		}

		if dep.Optional {
			metadata["optional"] = "true"
		}

		depArtifact := m.CreateArtifact(
			dep.ArtifactID,
			dep.Version,
			artifact.TypeMavenPackage,
			path,
			source,
			metadata,
		)
		artifacts = append(artifacts, depArtifact)
	}

	return artifacts, nil
}

// CanScan determines if this scanner can handle the given file
func (m *MavenScanner) CanScan(path string, filename string) bool {
	return m.MatchesFile(filename, path)
}

// ScanFile scans a specific file for artifacts
func (m *MavenScanner) ScanFile(ctx context.Context, path string, source artifact.Source) ([]artifact.Artifact, error) {
	filename := filepath.Base(path)

	if filename == PomXMLFile {
		return m.parsePomXML(path, source)
	}

	return nil, nil
}
