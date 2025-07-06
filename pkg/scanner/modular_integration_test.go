package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/docker"
)

// TestModularArchitecture tests the basic functionality of the modular scanner architecture
func TestModularArchitecture(t *testing.T) {
	tmpDir := createTestDirectory(t)
	defer os.RemoveAll(tmpDir)

	dockerClient := docker.NewClient(docker.ClientOptions{})

	t.Run("DefaultManager", func(t *testing.T) {
		testDefaultManager(t, tmpDir, dockerClient)
	})

	t.Run("PackageOnlyManager", func(t *testing.T) {
		testPackageOnlyManager(t, tmpDir, dockerClient)
	})

	t.Run("InfrastructureOnlyManager", func(t *testing.T) {
		testInfrastructureOnlyManager(t, tmpDir, dockerClient)
	})

	t.Run("LanguageSpecificManager", func(t *testing.T) {
		testLanguageSpecificManager(t, tmpDir, dockerClient)
	})
}

// createTestDirectory creates a temporary directory with test files
func createTestDirectory(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "cartographer-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	testFiles := map[string]string{
		"package.json": `{
			"name": "test-project",
			"version": "1.0.0",
			"dependencies": {
				"express": "^4.18.0",
				"lodash": "^4.17.21"
			}
		}`,
		"go.mod": `module test-project
		
go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/stretchr/testify v1.8.4
)`,
		"requirements.txt": `requests==2.28.1
flask==2.2.2
pytest==7.1.3`,
		"Dockerfile": `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]`,
		"docker-compose.yml": `version: '3.8'
services:
  web:
    build: .
    ports:
      - "3000:3000"
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: testdb`,
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	return tmpDir
}

// testDefaultManager tests the default manager functionality
func testDefaultManager(t *testing.T, tmpDir string, dockerClient *docker.Client) {
	manager := NewModularDefaultManager(dockerClient)

	ctx := context.Background()
	collection, err := manager.ScanFilesystem(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Default manager scan failed: %v", err)
	}

	if len(collection.Artifacts) == 0 {
		t.Error("Expected artifacts to be found, but got none")
	}

	// Check for package manager artifacts
	var foundPackageArtifacts bool
	for _, art := range collection.Artifacts {
		if art.Type == artifact.TypeNpmPackage ||
			art.Type == artifact.TypeGoModule ||
			art.Type == artifact.TypePythonPackage {
			foundPackageArtifacts = true
			break
		}
	}

	if !foundPackageArtifacts {
		t.Error("Expected to find package manager artifacts")
	}

	t.Logf("Default manager found %d artifacts", len(collection.Artifacts))
}

// testPackageOnlyManager tests the package-only manager functionality
func testPackageOnlyManager(t *testing.T, tmpDir string, dockerClient *docker.Client) {
	manager := NewModularPackageOnlyManager(dockerClient)

	ctx := context.Background()
	collection, err := manager.ScanFilesystem(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Package-only manager scan failed: %v", err)
	}

	// Should only find package artifacts, no infrastructure
	for _, art := range collection.Artifacts {
		if art.Type == artifact.TypeDockerfile || art.Type == artifact.TypeDockerCompose {
			t.Errorf("Package-only manager should not find infrastructure artifacts, but found %s", art.Type)
		}
	}

	t.Logf("Package-only manager found %d artifacts", len(collection.Artifacts))
}

// testInfrastructureOnlyManager tests the infrastructure-only manager functionality
func testInfrastructureOnlyManager(t *testing.T, tmpDir string, dockerClient *docker.Client) {
	manager := NewModularInfrastructureOnlyManager(dockerClient)

	ctx := context.Background()
	collection, err := manager.ScanFilesystem(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Infrastructure-only manager scan failed: %v", err)
	}

	// Should find Docker artifacts
	var foundDockerArtifacts bool
	for _, art := range collection.Artifacts {
		if art.Type == artifact.TypeDockerfile || art.Type == artifact.TypeDockerCompose {
			foundDockerArtifacts = true
			break
		}
	}

	if !foundDockerArtifacts {
		t.Error("Expected to find Docker artifacts")
	}

	t.Logf("Infrastructure-only manager found %d artifacts", len(collection.Artifacts))
}

// testLanguageSpecificManager tests the language-specific manager functionality
func testLanguageSpecificManager(t *testing.T, tmpDir string, dockerClient *docker.Client) {
	manager := NewModularLanguageSpecificManager(dockerClient, []string{"javascript", "go"})

	ctx := context.Background()
	collection, err := manager.ScanFilesystem(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Language-specific manager scan failed: %v", err)
	}

	// Should find NPM and Go artifacts, but not Python
	var foundNpm, foundGo, foundPython bool
	for _, art := range collection.Artifacts {
		switch art.Type {
		case artifact.TypeNpmPackage:
			foundNpm = true
		case artifact.TypeGoModule:
			foundGo = true
		case artifact.TypePythonPackage:
			foundPython = true
		}
	}

	if !foundNpm {
		t.Error("Expected to find NPM artifacts")
	}
	if !foundGo {
		t.Error("Expected to find Go artifacts")
	}
	if foundPython {
		t.Error("Should not find Python artifacts in JS/Go-only scan")
	}

	t.Logf("Language-specific manager found %d artifacts", len(collection.Artifacts))
}

// TestDockerfileScanner tests the Dockerfile parsing functionality
func TestDockerfileScanner(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cartographer-dockerfile-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dockerfileContent := `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000 8080
USER node
ENTRYPOINT ["node"]
CMD ["server.js"]`

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("Failed to create Dockerfile: %v", err)
	}

	dockerClient := docker.NewClient(docker.ClientOptions{})
	manager := NewModularInfrastructureOnlyManager(dockerClient)

	ctx := context.Background()
	collection, err := manager.ScanFilesystem(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Dockerfile scan failed: %v", err)
	}

	// Find the Dockerfile artifact
	var dockerfileArtifact *artifact.Artifact
	for _, art := range collection.Artifacts {
		if art.Type == artifact.TypeDockerfile {
			dockerfileArtifact = &art
			break
		}
	}

	if dockerfileArtifact == nil {
		t.Fatal("Expected to find Dockerfile artifact")
	}

	// Check extracted metadata
	if dockerfileArtifact.Metadata["base_images"] != "node:18-alpine" {
		t.Errorf("Expected base_images to be 'node:18-alpine', got '%s'", dockerfileArtifact.Metadata["base_images"])
	}

	if dockerfileArtifact.Metadata["exposed_ports"] != "3000, 8080" {
		t.Errorf("Expected exposed_ports to be '3000, 8080', got '%s'", dockerfileArtifact.Metadata["exposed_ports"])
	}

	if dockerfileArtifact.Metadata["workdir"] != "/app" {
		t.Errorf("Expected workdir to be '/app', got '%s'", dockerfileArtifact.Metadata["workdir"])
	}

	if dockerfileArtifact.Metadata["user"] != "node" {
		t.Errorf("Expected user to be 'node', got '%s'", dockerfileArtifact.Metadata["user"])
	}

	t.Logf("Dockerfile metadata: %+v", dockerfileArtifact.Metadata)
}
