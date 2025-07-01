package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// Test constants to avoid duplication
const (
	testReadmeFile    = "readme.md"
	testAPIJSONFile   = "api.json"
	testGuideFile     = "guide.md"
	testUnknownFile   = "unknown.xyz"
	licenseTypeGPL3   = "GPL-3.0"
	licenseTypeMIT    = "MIT"
	licenseTypeApache = "Apache-2.0"
	licenseTypeBSD3   = "BSD-3-Clause"
	testReadmeMD      = "README.md"
	testConfigJSON    = "config.json"
)

func TestNewLicenseAnalyzer(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	if analyzer == nil {
		t.Fatal("NewLicenseAnalyzer() returned nil")
	}

	if analyzer.licensePatterns == nil {
		t.Fatal("licensePatterns not initialized")
	}

	// Test that common license patterns are present
	expectedLicenses := []string{licenseTypeMIT, licenseTypeApache, licenseTypeGPL3, licenseTypeBSD3}
	for _, license := range expectedLicenses {
		if _, exists := analyzer.licensePatterns[license]; !exists {
			t.Errorf("Expected license pattern %s not found", license)
		}
	}
}

func TestLicenseAnalyzerName(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	expected := "license-analyzer"

	if analyzer.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, analyzer.Name())
	}
}

func TestLicenseAnalyzerSupportedTypes(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	supportedTypes := analyzer.SupportedTypes()

	expectedTypes := []artifact.Type{
		artifact.TypeLicense,
		artifact.TypeReadme,
		artifact.TypeChangelog,
		artifact.TypeDocumentation,
		artifact.TypeManPage,
		artifact.TypeAPISpec,
		artifact.TypeSchemaFile,
	}

	if len(supportedTypes) != len(expectedTypes) {
		t.Errorf("Expected %d supported types, got %d", len(expectedTypes), len(supportedTypes))
	}

	// Convert to map for easier lookup
	typeMap := make(map[artifact.Type]bool)
	for _, t := range supportedTypes {
		typeMap[t] = true
	}

	for _, expectedType := range expectedTypes {
		if !typeMap[expectedType] {
			t.Errorf("Expected type %s not found in supported types", expectedType)
		}
	}
}

func TestLicenseAnalyzerIsLicenseFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected bool
	}{
		{"license", true},
		{"licence", true},
		{"license.txt", true},
		{"license.md", true},
		{"copying", true},
		{"unlicense", true},
		{testReadmeFile, false},
		{"main.go", false},
		{"license-info.txt", false},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.isLicenseFile(tc.fileName)
			if result != tc.expected {
				t.Errorf("isLicenseFile(%s) = %v, expected %v", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsReadmeFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected bool
	}{
		{"readme", true},
		{"readme", true}, // testing lowercase handling
		{testReadmeFile, true},
		{"readme.txt", true},
		{"readme.rst", true},
		{"readmebutnotreally", true}, // starts with readme
		{"notreadme", false},
		{"license", false},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.isReadmeFile(tc.fileName)
			if result != tc.expected {
				t.Errorf("isReadmeFile(%s) = %v, expected %v", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsChangelogFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected bool
	}{
		{"changelog", true},
		{"changelog", true}, // testing lowercase handling
		{"changelog.md", true},
		{"changes", true},
		{"changes", true}, // testing lowercase handling
		{"history", true},
		{"news", true},
		{"releases", true},
		{"changelog.txt", true},
		{"changes.rst", true},
		{"readme", false},
		{"license", false},
		{"changelog-old", false},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.isChangelogFile(tc.fileName)
			if result != tc.expected {
				t.Errorf("isChangelogFile(%s) = %v, expected %v", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsDocumentationFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		path     string
		expected bool
	}{
		{testGuideFile, "/project/docs/guide.md", true},
		{"tutorial.rst", "/project/doc/tutorial.rst", true},
		{"manual.txt", "/project/documentation/manual.txt", true},
		{"help.html", "/project/help/help.html", true},
		{"api.md", "/project/manual/api.md", true},
		{testReadmeFile, "/project/src/readme.md", false}, // not in doc directory
		{"code.go", "/project/docs/code.go", false},       // wrong extension
		{testGuideFile, "/project/src/guide.md", false},   // not in doc directory
	}

	for _, tc := range testCases {
		t.Run(tc.fileName+"_"+tc.path, func(t *testing.T) {
			result := analyzer.isDocumentationFile(tc.fileName, tc.path)
			if result != tc.expected {
				t.Errorf("isDocumentationFile(%s, %s) = %v, expected %v", tc.fileName, tc.path, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsManPage(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		path     string
		expected bool
	}{
		{"ls.1", "/usr/share/man/man1/ls.1", true},
		{"printf.3", "/usr/share/man/man3/printf.3", true},
		{"bash.1.gz", "/usr/share/man/man1/bash.1.gz", true},
		{"guide.1", "/project/docs/guide.1", false},         // not in man directory
		{testReadmeFile, "/usr/share/man/readme.md", false}, // wrong extension
		{"ls.1", "/project/src/ls.1", false},                // not in man directory
	}

	for _, tc := range testCases {
		t.Run(tc.fileName+"_"+tc.path, func(t *testing.T) {
			result := analyzer.isManPage(tc.fileName, tc.path)
			if result != tc.expected {
				t.Errorf("isManPage(%s, %s) = %v, expected %v", tc.fileName, tc.path, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsAPISpec(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected bool
	}{
		{"swagger.json", true},
		{"swagger.yaml", true},
		{"openapi.yml", true},
		{testAPIJSONFile, true},
		{"spec.yaml", true},
		{"my-openapi.json", true}, // contains openapi
		{"my-swagger.yml", true},  // contains swagger
		{"user-api.yaml", true},   // contains api + yaml
		{testReadmeFile, false},
		{testConfigJSON, false},
		{"api.txt", false}, // api but wrong extension
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.isAPISpec(tc.fileName)
			if result != tc.expected {
				t.Errorf("isAPISpec(%s) = %v, expected %v", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerIsSchemaFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		path     string
		expected bool
	}{
		{"schema.json", "/project/schema.json", true},
		{"schema.yaml", "/project/schema.yaml", true},
		{"schema.xsd", "/project/schema.xsd", true},
		{"user.graphql", "/project/user.graphql", true},
		{"api.gql", "/project/api.gql", true},
		{"user-schema.json", "/project/user-schema.json", true}, // contains schema
		{"user.json", "/project/schema/user.json", true},        // in schema directory
		{testConfigJSON, "/project/schema/config.json", true},   // in schema directory
		{testReadmeFile, "/project/readme.md", false},
		{testConfigJSON, "/project/config.json", false},
		{"schema.txt", "/project/schema.txt", false}, // schema but wrong extension
	}

	for _, tc := range testCases {
		t.Run(tc.fileName+"_"+tc.path, func(t *testing.T) {
			result := analyzer.isSchemaFile(tc.fileName, tc.path)
			if result != tc.expected {
				t.Errorf("isSchemaFile(%s, %s) = %v, expected %v", tc.fileName, tc.path, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerDetectLicenseType(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		name            string
		content         string
		expectedLicense string
	}{
		{
			name:            "MIT License",
			content:         "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy",
			expectedLicense: licenseTypeMIT,
		},
		{
			name:            "Apache 2.0",
			content:         "Apache License, Version 2.0\n\nLicensed under the Apache License",
			expectedLicense: licenseTypeApache,
		},
		{
			name:            licenseTypeGPL3,
			content:         "GNU GENERAL PUBLIC LICENSE Version 3",
			expectedLicense: licenseTypeGPL3,
		},
		{
			name:            "Unknown License",
			content:         "This is some random text that doesn't match any known license",
			expectedLicense: "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temporary file with test content
			tempDir := t.TempDir()
			testFile := filepath.Join(tempDir, "license")
			err := os.WriteFile(testFile, []byte(tc.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result := analyzer.detectLicenseType(testFile)
			if result != tc.expectedLicense {
				t.Errorf("detectLicenseType() = %s, expected %s", result, tc.expectedLicense)
			}
		})
	}
}

func TestLicenseAnalyzerGetDocumentFormat(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected string
	}{
		{testReadmeFile, "markdown"},
		{"guide.rst", "restructuredtext"},
		{"doc.html", "html"},
		{"manual.tex", "latex"},
		{"help.adoc", "asciidoc"},
		{"notes.txt", "plain-text"},
		{testUnknownFile, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.getDocumentFormat(tc.fileName)
			if result != tc.expected {
				t.Errorf("getDocumentFormat(%s) = %s, expected %s", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerGetAPISpecFormat(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected string
	}{
		{testAPIJSONFile, "json"},
		{"spec.yaml", "yaml"},
		{"openapi.yml", "yaml"},
		{testUnknownFile, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.getAPISpecFormat(tc.fileName)
			if result != tc.expected {
				t.Errorf("getAPISpecFormat(%s) = %s, expected %s", tc.fileName, result, tc.expected)
			}
		})
	}
}

func TestLicenseAnalyzerGetSchemaFormat(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	testCases := []struct {
		fileName string
		expected string
	}{
		{"schema.json", "json-schema"},
		{"schema.yaml", "yaml-schema"},
		{"schema.xsd", "xml-schema"},
		{"api.graphql", "graphql"},
		{"schema.gql", "graphql"},
		{testUnknownFile, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := analyzer.getSchemaFormat(tc.fileName)
			if result != tc.expected {
				t.Errorf("getSchemaFormat(%s) = %s, expected %s", tc.fileName, result, tc.expected)
			}
		})
	}
}

// Helper function to create test files
func createTestFiles(t *testing.T, tempDir string) {
	testFiles := map[string]string{
		"LICENSE":          "MIT License\n\nPermission is hereby granted, free of charge",
		testReadmeMD:       "# Test Project\n\nThis is a test project",
		"CHANGELOG.md":     "# Changelog\n\n## v1.0.0\n- Initial release",
		"docs/guide.md":    "# User Guide\n\nThis is the user guide",
		"docs/api.json":    `{"openapi": "3.0.0", "info": {"title": "Test API"}}`,
		"schema/user.json": `{"type": "object", "properties": {"name": {"type": "string"}}}`,
		"man/man1/test.1":  ".TH TEST 1\n.SH NAME\ntest - test command",
		"src/main.go":      "package main\n\nfunc main() {}",
	}

	for filePath, content := range testFiles {
		fullPath := filepath.Join(tempDir, filePath)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", fullPath, err)
		}
	}
}

// Helper function to validate artifacts
func validateArtifacts(t *testing.T, artifacts []artifact.Artifact, tempDir string) {
	expectedArtifacts := map[string]artifact.Type{
		"LICENSE":      artifact.TypeLicense,
		testReadmeMD:   artifact.TypeReadme,
		"CHANGELOG.md": artifact.TypeChangelog,
		"guide.md":     artifact.TypeDocumentation,
		"api.json":     artifact.TypeAPISpec,
		"user.json":    artifact.TypeSchemaFile,
		"test.1":       artifact.TypeManPage,
	}

	if len(artifacts) != len(expectedArtifacts) {
		t.Errorf("Expected %d artifacts, got %d", len(expectedArtifacts), len(artifacts))
	}

	artifactMap := make(map[string]artifact.Artifact)
	for _, art := range artifacts {
		artifactMap[art.Name] = art
	}

	for expectedName, expectedType := range expectedArtifacts {
		validateSingleArtifact(t, artifactMap, expectedName, expectedType, tempDir)
	}
}

// Helper function to validate a single artifact
func validateSingleArtifact(t *testing.T, artifactMap map[string]artifact.Artifact, expectedName string, expectedType artifact.Type, tempDir string) {
	art, exists := artifactMap[expectedName]
	if !exists {
		t.Errorf("Expected artifact %s not found", expectedName)
		return
	}

	if art.Type != expectedType {
		t.Errorf("Artifact %s: expected type %s, got %s", expectedName, expectedType, art.Type)
	}

	if art.Source.Location != tempDir {
		t.Errorf("Artifact %s: expected source location %s, got %s", expectedName, tempDir, art.Source.Location)
	}

	if art.Size == 0 {
		t.Errorf("Artifact %s: expected non-zero size", expectedName)
	}

	if art.ModTime == nil {
		t.Errorf("Artifact %s: expected non-nil ModTime", expectedName)
	}

	if art.Metadata == nil {
		t.Errorf("Artifact %s: expected non-nil metadata", expectedName)
	}
}

func TestLicenseAnalyzerScan(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	ctx := context.Background()

	tempDir := t.TempDir()
	createTestFiles(t, tempDir)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	artifacts, err := analyzer.Scan(ctx, source)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	validateArtifacts(t, artifacts, tempDir)

	// Test specific metadata
	artifactMap := make(map[string]artifact.Artifact)
	for _, art := range artifacts {
		artifactMap[art.Name] = art
	}

	if licenseArt, exists := artifactMap["LICENSE"]; exists {
		if licenseArt.Metadata["document_type"] != "license" {
			t.Errorf("LICENSE: expected document_type 'license', got %s", licenseArt.Metadata["document_type"])
		}
		if licenseArt.Metadata["license_type"] != licenseTypeMIT {
			t.Errorf("LICENSE: expected license_type '%s', got %s", licenseTypeMIT, licenseArt.Metadata["license_type"])
		}
	}

	if readmeArt, exists := artifactMap[testReadmeMD]; exists {
		if readmeArt.Metadata["format"] != "markdown" {
			t.Errorf("%s: expected format 'markdown', got %s", testReadmeMD, readmeArt.Metadata["format"])
		}
	}
}

func TestLicenseAnalyzerScanEmptyDirectory(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	ctx := context.Background()

	tempDir := t.TempDir()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	artifacts, err := analyzer.Scan(ctx, source)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Expected 0 artifacts in empty directory, got %d", len(artifacts))
	}
}

func TestLicenseAnalyzerScanNonExistentDirectory(t *testing.T) {
	analyzer := NewLicenseAnalyzer()
	ctx := context.Background()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/nonexistent/directory",
	}

	artifacts, err := analyzer.Scan(ctx, source)
	if err == nil {
		t.Fatal("Expected error for non-existent directory, got nil")
	}

	if artifacts != nil {
		t.Errorf("Expected nil artifacts for failed scan, got %v", artifacts)
	}
}

func TestLicenseAnalyzerDetectLicenseTypeNonExistentFile(t *testing.T) {
	analyzer := NewLicenseAnalyzer()

	result := analyzer.detectLicenseType("/nonexistent/file")
	if result != "" {
		t.Errorf("Expected empty string for non-existent file, got %s", result)
	}
}

// Benchmark tests
func BenchmarkLicenseAnalyzerIsLicenseFile(b *testing.B) {
	analyzer := NewLicenseAnalyzer()
	testFiles := []string{"license", "LICENSE", "readme.md", "main.go", "license.txt"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, file := range testFiles {
			analyzer.isLicenseFile(file)
		}
	}
}

func BenchmarkLicenseAnalyzerDetectLicenseType(b *testing.B) {
	analyzer := NewLicenseAnalyzer()

	// Create a temporary file with MIT license content
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "license")
	content := "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy"
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.detectLicenseType(testFile)
	}
}
