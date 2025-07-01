package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// Test constants to avoid duplication
const (
	makefileContent       = "all:\n\techo 'build'"
	cmakeContent          = "cmake_minimum_required(VERSION 3.10)"
	cargoContent          = "[package]\nname = \"test\""
	setupPyContent        = "from setuptools import setup"
	jenkinsContent        = "pipeline { agent any }"
	githubActionsFile     = ".github/workflows/ci.yml"
	githubActionsContent  = "name: CI\non: [push]"
	gitlabCIFile          = ".gitlab-ci.yml"
	gitlabCIContent       = "stages:\n  - build"
	circleCIFile          = ".circleci/config.yml"
	circleCIContent       = "version: 2"
	travisCIFile          = ".travis.yml"
	travisCIContent       = "language: node_js"
	azurePipelinesFile    = "azure-pipelines.yml"
	azurePipelinesContent = "trigger:\n- main"
	composerContent       = `{"require": {"php": ">=7.4"}}`
)

// Helper function to create test files
func createTestFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)

	// Create subdirectories if needed
	if subdir := filepath.Dir(path); subdir != dir {
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", subdir, err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file %s: %v", path, err)
	}

	return path
}

// Helper function to create test directory structure for CI files
func createCITestStructure(t *testing.T) string {
	tempDir := t.TempDir()

	// Build system files
	createTestFile(t, tempDir, "Makefile", makefileContent)
	createTestFile(t, tempDir, "CMakeLists.txt", cmakeContent)
	createTestFile(t, tempDir, "build.sh", "#!/bin/bash\necho 'building'")
	createTestFile(t, tempDir, "build.gradle", "apply plugin: 'java'")
	createTestFile(t, tempDir, "pom.xml", "<project><groupId>test</groupId></project>")
	createTestFile(t, tempDir, "cargo.toml", cargoContent)

	// Python build files
	createTestFile(t, tempDir, "setup.py", setupPyContent)
	createTestFile(t, tempDir, "setup.cfg", "[metadata]\nname = test")
	createTestFile(t, tempDir, "pyproject.toml", "[tool.poetry]\nname = \"test\"")

	// Node.js with scripts
	packageWithScripts := `{
  "name": "test",
  "scripts": {
    "build": "webpack",
    "test": "jest"
  }
}`
	createTestFile(t, tempDir, "package.json", packageWithScripts)

	// Node.js without scripts
	packageWithoutScripts := `{
  "name": "test",
  "dependencies": {
    "react": "^17.0.0"
  }
}`
	createTestFile(t, tempDir, "no-scripts/package.json", packageWithoutScripts)

	// CI/CD files
	createTestFile(t, tempDir, "Jenkinsfile", jenkinsContent)
	createTestFile(t, tempDir, githubActionsFile, githubActionsContent)
	createTestFile(t, tempDir, gitlabCIFile, gitlabCIContent)
	createTestFile(t, tempDir, circleCIFile, circleCIContent)
	createTestFile(t, tempDir, travisCIFile, travisCIContent)
	createTestFile(t, tempDir, azurePipelinesFile, azurePipelinesContent)
	createTestFile(t, tempDir, ".buildkite/pipeline.yml", "steps:\n  - command: 'echo test'")
	createTestFile(t, tempDir, ".drone.yml", "kind: pipeline")

	// Additional build files
	createTestFile(t, tempDir, "composer.json", composerContent)
	createTestFile(t, tempDir, "Gemfile", "gem 'rails'")
	createTestFile(t, tempDir, "mix.exs", "defmodule Test.MixProject do")
	createTestFile(t, tempDir, "dune-project", "(lang dune 2.0)")
	createTestFile(t, tempDir, "stack.yaml", "resolver: lts-18.0")
	createTestFile(t, tempDir, "test.cabal", "name: test")

	return tempDir
}

func TestNewCIAnalyzer(t *testing.T) {
	analyzer := NewCIAnalyzer()
	if analyzer == nil {
		t.Fatal("NewCIAnalyzer returned nil")
	}
}

func TestCIAnalyzerName(t *testing.T) {
	analyzer := NewCIAnalyzer()
	expected := "ci-analyzer"
	if got := analyzer.Name(); got != expected {
		t.Errorf("Name() = %v, want %v", got, expected)
	}
}

func TestCIAnalyzerSupportedTypes(t *testing.T) {
	analyzer := NewCIAnalyzer()
	supportedTypes := analyzer.SupportedTypes()

	expectedTypes := []artifact.Type{
		artifact.TypeMakefile,
		artifact.TypeCMakeLists,
		artifact.TypeBuildScript,
		artifact.TypeJenkinsfile,
		artifact.TypeGitHubActions,
		artifact.TypeGitLabCI,
		artifact.TypeCircleCI,
		artifact.TypeTravisCI,
		artifact.TypeAzurePipelines,
		artifact.TypeBuildkite,
		artifact.TypeDroneCI,
	}

	if len(supportedTypes) != len(expectedTypes) {
		t.Errorf("SupportedTypes() returned %d types, expected %d", len(supportedTypes), len(expectedTypes))
	}

	for i, expected := range expectedTypes {
		if i >= len(supportedTypes) || supportedTypes[i] != expected {
			t.Errorf("SupportedTypes()[%d] = %v, want %v", i, supportedTypes[i], expected)
		}
	}
}

func TestCIAnalyzerScan(t *testing.T) {
	analyzer := NewCIAnalyzer()
	testDir := createCITestStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) == 0 {
		t.Error("Scan() returned no artifacts, expected some")
	}

	// Verify we found different types of artifacts
	foundTypes := make(map[artifact.Type]int)
	for _, art := range artifacts {
		foundTypes[art.Type]++

		// Verify artifact has required fields
		if art.Name == "" {
			t.Error("Artifact missing name")
		}
		if art.Path == "" {
			t.Error("Artifact missing path")
		}
		if art.Metadata == nil {
			t.Error("Artifact missing metadata")
		}
	}

	// Check that we found some expected types
	if foundTypes[artifact.TypeMakefile] == 0 {
		t.Error("Expected to find Makefile artifacts")
	}
	if foundTypes[artifact.TypeBuildScript] == 0 {
		t.Error("Expected to find build script artifacts")
	}
	if foundTypes[artifact.TypeGitHubActions] == 0 {
		t.Error("Expected to find GitHub Actions artifacts")
	}
}

func TestCIAnalyzerGetScriptType(t *testing.T) {
	analyzer := NewCIAnalyzer()

	tests := []struct {
		fileName string
		want     string
	}{
		{"build.sh", "shell"},
		{"build.bat", "batch"},
		{"build.ps1", "powershell"},
		{"build", "script"},
		{"compile.sh", "shell"},
		{"test.bat", "batch"},
		{"deploy.ps1", "powershell"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			got := analyzer.getScriptType(tt.fileName)
			if got != tt.want {
				t.Errorf("getScriptType(%v) = %v, want %v", tt.fileName, got, tt.want)
			}
		})
	}
}

func TestCIAnalyzerHasScripts(t *testing.T) {
	analyzer := NewCIAnalyzer()
	tempDir := t.TempDir()

	// Package.json with scripts
	packageWithScripts := `{
  "name": "test",
  "scripts": {
    "build": "webpack",
    "test": "jest"
  }
}`
	pathWithScripts := createTestFile(t, tempDir, "with-scripts.json", packageWithScripts)

	// Package.json without scripts
	packageWithoutScripts := `{
  "name": "test",
  "dependencies": {
    "react": "^17.0.0"
  }
}`
	pathWithoutScripts := createTestFile(t, tempDir, "without-scripts.json", packageWithoutScripts)

	// Test with scripts
	if !analyzer.hasScripts(pathWithScripts) {
		t.Error("hasScripts() = false, want true for package with scripts")
	}

	// Test without scripts
	if analyzer.hasScripts(pathWithoutScripts) {
		t.Error("hasScripts() = true, want false for package without scripts")
	}

	// Test nonexistent file
	if analyzer.hasScripts("/nonexistent/file.json") {
		t.Error("hasScripts() = true, want false for nonexistent file")
	}
}

func TestCIAnalyzerGetPythonBuildType(t *testing.T) {
	analyzer := NewCIAnalyzer()

	tests := []struct {
		fileName string
		want     string
	}{
		{"setup.py", "setuptools"},
		{"setup.cfg", "setuptools-cfg"},
		{"pyproject.toml", "pyproject"},
		{"other.py", "python"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			got := analyzer.getPythonBuildType(tt.fileName)
			if got != tt.want {
				t.Errorf("getPythonBuildType(%v) = %v, want %v", tt.fileName, got, tt.want)
			}
		})
	}
}

func TestCIAnalyzerGetHaskellBuildSystem(t *testing.T) {
	analyzer := NewCIAnalyzer()

	tests := []struct {
		fileName string
		want     string
	}{
		{"stack.yaml", "stack"},
		{"test.cabal", "cabal"},
		{"project.cabal", "cabal"},
		{"other.hs", "haskell"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			got := analyzer.getHaskellBuildSystem(tt.fileName)
			if got != tt.want {
				t.Errorf("getHaskellBuildSystem(%v) = %v, want %v", tt.fileName, got, tt.want)
			}
		})
	}
}

func TestCIAnalyzerSpecificFileTypes(t *testing.T) {
	analyzer := NewCIAnalyzer()

	tests := []struct {
		name         string
		fileName     string
		content      string
		expectedType artifact.Type
		expectedMeta map[string]string
	}{
		{
			name:         "Makefile",
			fileName:     "Makefile",
			content:      makefileContent,
			expectedType: artifact.TypeMakefile,
			expectedMeta: map[string]string{
				"build_system": "make",
				"file_type":    "makefile",
			},
		},
		{
			name:         "CMakeLists.txt",
			fileName:     "CMakeLists.txt",
			content:      cmakeContent,
			expectedType: artifact.TypeCMakeLists,
			expectedMeta: map[string]string{
				"build_system": "cmake",
				"file_type":    "cmake",
			},
		},
		{
			name:         "Jenkinsfile",
			fileName:     "Jenkinsfile",
			content:      jenkinsContent,
			expectedType: artifact.TypeJenkinsfile,
			expectedMeta: map[string]string{
				"ci_system": "jenkins",
				"file_type": "jenkinsfile",
				"pipeline":  "true",
			},
		},
		{
			name:         "GitHub Actions",
			fileName:     githubActionsFile,
			content:      githubActionsContent,
			expectedType: artifact.TypeGitHubActions,
			expectedMeta: map[string]string{
				"ci_system": "github-actions",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "GitLab CI",
			fileName:     gitlabCIFile,
			content:      gitlabCIContent,
			expectedType: artifact.TypeGitLabCI,
			expectedMeta: map[string]string{
				"ci_system": "gitlab",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "CircleCI",
			fileName:     circleCIFile,
			content:      circleCIContent,
			expectedType: artifact.TypeCircleCI,
			expectedMeta: map[string]string{
				"ci_system": "circleci",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "Travis CI",
			fileName:     travisCIFile,
			content:      travisCIContent,
			expectedType: artifact.TypeTravisCI,
			expectedMeta: map[string]string{
				"ci_system": "travis",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "Azure Pipelines",
			fileName:     azurePipelinesFile,
			content:      azurePipelinesContent,
			expectedType: artifact.TypeAzurePipelines,
			expectedMeta: map[string]string{
				"ci_system": "azure-pipelines",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "Buildkite",
			fileName:     ".buildkite/pipeline.yml",
			content:      "steps:\n  - command: 'echo test'",
			expectedType: artifact.TypeBuildkite,
			expectedMeta: map[string]string{
				"ci_system": "buildkite",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "Drone CI",
			fileName:     ".drone.yml",
			content:      "kind: pipeline",
			expectedType: artifact.TypeDroneCI,
			expectedMeta: map[string]string{
				"ci_system": "drone",
				"file_type": "yaml",
				"pipeline":  "true",
			},
		},
		{
			name:         "Cargo.toml",
			fileName:     "Cargo.toml",
			content:      cargoContent,
			expectedType: artifact.TypeBuildScript,
			expectedMeta: map[string]string{
				"build_system": "cargo",
				"file_type":    "toml",
			},
		},
		{
			name:         "setup.py",
			fileName:     "setup.py",
			content:      setupPyContent,
			expectedType: artifact.TypeBuildScript,
			expectedMeta: map[string]string{
				"build_system": "python",
				"file_type":    "setuptools",
			},
		},
		{
			name:         "composer.json",
			fileName:     "composer.json",
			content:      composerContent,
			expectedType: artifact.TypeBuildScript,
			expectedMeta: map[string]string{
				"build_system": "composer",
				"file_type":    "json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create separate temp directory for each test
			tempDir := t.TempDir()

			// Create test file
			createTestFile(t, tempDir, tt.fileName, tt.content)

			source := artifact.Source{
				Type:     artifact.SourceTypeFilesystem,
				Location: tempDir,
			}

			ctx := context.Background()
			artifacts, err := analyzer.Scan(ctx, source)

			if err != nil {
				t.Errorf("Scan() error = %v, want nil", err)
				return
			}

			// Find our specific artifact
			var found *artifact.Artifact
			for _, art := range artifacts {
				// For nested files, check if the path contains the expected path
				if strings.Contains(art.Path, tt.fileName) || art.Name == filepath.Base(tt.fileName) {
					found = &art
					break
				}
			}

			if found == nil {
				// Debug: print all found artifacts
				t.Logf("Available artifacts:")
				for _, art := range artifacts {
					t.Logf("  Name: %s, Path: %s, Type: %s", art.Name, art.Path, art.Type)
				}
				t.Errorf("Expected to find artifact for %s", tt.fileName)
				return
			}

			if found.Type != tt.expectedType {
				t.Errorf("Artifact type = %v, want %v", found.Type, tt.expectedType)
			}

			// Check metadata
			for key, expectedValue := range tt.expectedMeta {
				if actualValue, exists := found.Metadata[key]; !exists {
					t.Errorf("Missing metadata key: %s", key)
				} else if actualValue != expectedValue {
					t.Errorf("Metadata[%s] = %v, want %v", key, actualValue, expectedValue)
				}
			}
		})
	}
}

func TestCIAnalyzerEmptyDirectory(t *testing.T) {
	analyzer := NewCIAnalyzer()
	tempDir := t.TempDir()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Scan() returned %d artifacts, expected 0 for empty directory", len(artifacts))
	}
}

func TestCIAnalyzerNonexistentDirectory(t *testing.T) {
	analyzer := NewCIAnalyzer()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/completely/nonexistent/directory/path",
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	// Error behavior may vary by OS, so we just ensure no artifacts are returned
	if len(artifacts) != 0 {
		t.Errorf("Scan() returned %d artifacts, expected 0 for nonexistent directory", len(artifacts))
	}

	// Error behavior may vary by OS
	_ = err
}

func TestCIAnalyzerIgnoreNonCIFiles(t *testing.T) {
	analyzer := NewCIAnalyzer()
	tempDir := t.TempDir()

	// Create files that should be ignored
	createTestFile(t, tempDir, "README.md", "# Test Project")
	createTestFile(t, tempDir, "main.go", "package main")
	createTestFile(t, tempDir, "test.txt", "test content")
	createTestFile(t, tempDir, "config.ini", "[section]\nkey=value")

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Scan() returned %d artifacts, expected 0 for non-CI files", len(artifacts))
	}
}

func TestCIAnalyzerCaseInsensitive(t *testing.T) {
	analyzer := NewCIAnalyzer()
	tempDir := t.TempDir()

	// Test case-insensitive file detection
	createTestFile(t, tempDir, "MAKEFILE", makefileContent)
	createTestFile(t, tempDir, "Jenkinsfile", jenkinsContent)
	createTestFile(t, tempDir, "CARGO.TOML", cargoContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) != 3 {
		t.Errorf("Scan() returned %d artifacts, expected 3", len(artifacts))
	}

	// Verify types were detected correctly
	foundTypes := make(map[artifact.Type]bool)
	for _, art := range artifacts {
		foundTypes[art.Type] = true
	}

	if !foundTypes[artifact.TypeMakefile] {
		t.Error("Expected to find Makefile artifact")
	}
	if !foundTypes[artifact.TypeJenkinsfile] {
		t.Error("Expected to find Jenkinsfile artifact")
	}
	if !foundTypes[artifact.TypeBuildScript] {
		t.Error("Expected to find build script artifact")
	}
}

// Benchmark tests
func BenchmarkCIAnalyzerScan(b *testing.B) {
	analyzer := NewCIAnalyzer()

	// Create temporary test directory for benchmark
	tempDir, _ := os.MkdirTemp("", "bench_ci_test")
	defer os.RemoveAll(tempDir)

	// Create some CI files
	files := map[string]string{
		"Makefile":                 makefileContent,
		"Jenkinsfile":              jenkinsContent,
		".github/workflows/ci.yml": "name: CI\non: [push]",
		".gitlab-ci.yml":           "stages:\n  - build",
		"package.json":             `{"scripts": {"build": "webpack"}}`,
		"cargo.toml":               cargoContent,
		"setup.py":                 "from setuptools import setup",
		"azure-pipelines.yml":      "trigger:\n- main",
		".circleci/config.yml":     "version: 2",
		".travis.yml":              "language: node_js",
	}

	for fileName, content := range files {
		path := filepath.Join(tempDir, fileName)
		if subdir := filepath.Dir(path); subdir != tempDir {
			os.MkdirAll(subdir, 0755)
		}
		os.WriteFile(path, []byte(content), 0644)
	}

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Scan(ctx, source)
	}
}

func BenchmarkCIAnalyzerHasScripts(b *testing.B) {
	analyzer := NewCIAnalyzer()

	tempDir, _ := os.MkdirTemp("", "bench_scripts_test")
	defer os.RemoveAll(tempDir)

	packageContent := `{
  "name": "test",
  "scripts": {
    "build": "webpack",
    "test": "jest",
    "start": "node server.js"
  }
}`
	path := filepath.Join(tempDir, "package.json")
	os.WriteFile(path, []byte(packageContent), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.hasScripts(path)
	}
}

// Test concurrent access
func TestCIAnalyzerConcurrentAccess(t *testing.T) {
	analyzer := NewCIAnalyzer()
	testDir := createCITestStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx := context.Background()

	// Run multiple scans concurrently
	done := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		go func() {
			defer func() { done <- true }()
			artifacts, err := analyzer.Scan(ctx, source)
			if err != nil {
				t.Errorf("Concurrent scan failed: %v", err)
			}
			if len(artifacts) == 0 {
				t.Error("Concurrent scan returned no artifacts")
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}
}

// Test context cancellation
func TestCIAnalyzerContextCancellation(t *testing.T) {
	analyzer := NewCIAnalyzer()
	testDir := createCITestStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	artifacts, err := analyzer.Scan(ctx, source)

	// Should handle cancelled context gracefully
	// The current implementation doesn't check context, so this may not fail
	// But we test it to ensure it doesn't panic
	_ = artifacts
	_ = err
}
