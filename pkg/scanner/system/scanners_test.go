package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

const (
	scannerFailedMsg = "Scanner failed: %v"
	testServiceName  = "test.service"
)

func TestBinaryScannerScan(t *testing.T) {
	tempDir := createTempDir(t)
	defer os.RemoveAll(tempDir)

	testBinary := createTestBinary(t, tempDir)
	libFile := createTestLibrary(t, tempDir)

	scanner := NewBinaryScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	artifacts, err := scanner.Scan(context.Background(), source)
	if err != nil {
		t.Fatalf(scannerFailedMsg, err)
	}

	t.Logf("Found %d artifacts", len(artifacts))
	for _, art := range artifacts {
		t.Logf("Artifact: %s (type: %s, path: %s)", art.Name, art.Type, art.Path)
	}

	if len(artifacts) == 0 {
		t.Fatal("Expected to find artifacts, but got none")
	}

	verifyBinaryArtifacts(t, artifacts, testBinary, libFile)
}

func createTempDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "binary_scanner_test")
	if err != nil {
		t.Fatal(err)
	}
	return tempDir
}

func createTestBinary(t *testing.T, tempDir string) string {
	binDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	testBinary := filepath.Join(binDir, "testapp")
	if err := os.WriteFile(testBinary, []byte("#!/bin/bash\necho hello"), 0755); err != nil {
		t.Fatal(err)
	}
	return testBinary
}

func createTestLibrary(t *testing.T, tempDir string) string {
	libFile := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(libFile, []byte("fake library"), 0644); err != nil {
		t.Fatal(err)
	}
	return libFile
}

func verifyBinaryArtifacts(t *testing.T, artifacts []artifact.Artifact, testBinary, libFile string) {
	foundBinary := false
	foundLibrary := false

	for _, art := range artifacts {
		if art.Name == "testapp" {
			foundBinary = true
			if art.Type != artifact.TypeExecutable {
				t.Errorf("Expected executable type, got %s", art.Type)
			}
		}
		if art.Name == "libtest.so" {
			foundLibrary = true
			if art.Type != artifact.TypeSharedLibrary {
				t.Errorf("Expected shared library type, got %s", art.Type)
			}
		}
	}

	if !foundBinary {
		t.Error("Expected to find test binary")
	}
	if !foundLibrary {
		t.Error("Expected to find test library")
	}
}

func TestServiceScannerScan(t *testing.T) {
	tempDir := createTempDir(t)
	defer os.RemoveAll(tempDir)

	createTestServiceFile(t, tempDir)

	scanner := NewServiceScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	artifacts, err := scanner.Scan(context.Background(), source)
	if err != nil {
		t.Fatalf(scannerFailedMsg, err)
	}

	verifyServiceArtifact(t, artifacts)
}

func createTestServiceFile(t *testing.T, tempDir string) {
	serviceContent := `[Unit]
Description=Test Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/test-daemon
User=nobody
Restart=always

[Install]
WantedBy=multi-user.target
`

	serviceFile := filepath.Join(tempDir, testServiceName)
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		t.Fatal(err)
	}
}

func verifyServiceArtifact(t *testing.T, artifacts []artifact.Artifact) {
	if len(artifacts) != 1 {
		t.Fatalf("Expected 1 artifact, got %d", len(artifacts))
	}

	art := artifacts[0]
	if art.Name != testServiceName {
		t.Errorf("Expected name '%s', got %s", testServiceName, art.Name)
	}

	if art.Type != artifact.TypeSystemdUnit {
		t.Errorf("Expected systemd unit type, got %s", art.Type)
	}

	verifyServiceMetadata(t, art)
}

func verifyServiceMetadata(t *testing.T, art artifact.Artifact) {
	if desc, ok := art.Metadata["description"]; !ok || desc != "Test Service" {
		t.Errorf("Expected description 'Test Service', got %s", desc)
	}

	if execStart, ok := art.Metadata["exec_start"]; !ok || execStart != "/usr/bin/test-daemon" {
		t.Errorf("Expected exec_start '/usr/bin/test-daemon', got %s", execStart)
	}
}

func TestConfigScannerScan(t *testing.T) {
	tempDir := createTempDir(t)
	defer os.RemoveAll(tempDir)

	createTestConfigFiles(t, tempDir)

	scanner := NewConfigScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	artifacts, err := scanner.Scan(context.Background(), source)
	if err != nil {
		t.Fatalf(scannerFailedMsg, err)
	}

	verifyConfigArtifacts(t, artifacts)
}

func createTestConfigFiles(t *testing.T, tempDir string) {
	// Create test INI config file
	iniContent := `[database]
host=localhost
port=5432
name=testdb

[logging]
level=info
file=/var/log/app.log
`

	iniFile := filepath.Join(tempDir, "app.conf")
	if err := os.WriteFile(iniFile, []byte(iniContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create test properties file
	propsContent := `server.port=8080
server.host=localhost
database.url=jdbc:postgresql://localhost/test
`

	propsFile := filepath.Join(tempDir, "application.properties")
	if err := os.WriteFile(propsFile, []byte(propsContent), 0644); err != nil {
		t.Fatal(err)
	}
}

func verifyConfigArtifacts(t *testing.T, artifacts []artifact.Artifact) {
	if len(artifacts) != 2 {
		t.Fatalf("Expected 2 artifacts, got %d", len(artifacts))
	}

	foundConf := false
	foundProps := false

	for _, art := range artifacts {
		if art.Type != artifact.TypeConfigFile {
			t.Errorf("Expected config file type, got %s", art.Type)
		}

		if art.Name == "app.conf" {
			foundConf = true
			verifyConfFormat(t, art)
		}
		if art.Name == "application.properties" {
			foundProps = true
			verifyPropsFormat(t, art)
		}
	}

	if !foundConf {
		t.Error("Expected to find app.conf")
	}
	if !foundProps {
		t.Error("Expected to find application.properties")
	}
}

func verifyConfFormat(t *testing.T, art artifact.Artifact) {
	if format, ok := art.Metadata["format"]; !ok || format != "conf" {
		t.Errorf("Expected format 'conf', got %s", format)
	}
	if sections, ok := art.Metadata["section_count"]; !ok || sections != "2" {
		t.Errorf("Expected 2 sections, got %s", sections)
	}
}

func verifyPropsFormat(t *testing.T, art artifact.Artifact) {
	if format, ok := art.Metadata["format"]; !ok || format != "properties" {
		t.Errorf("Expected format 'properties', got %s", format)
	}
}

func TestBinaryScannerDetectArchitecture(t *testing.T) {
	scanner := NewBinaryScanner()

	// Test with non-existent file
	arch := scanner.detectArchitecture("/non/existent/file")
	if arch != "unknown" {
		t.Errorf("Expected 'unknown' for non-existent file, got %s", arch)
	}

	// Create a temporary file with ELF-like header
	tempFile, err := os.CreateTemp("", "test_binary")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	// Write ELF header (32-bit)
	elfHeader := []byte{0x7f, 'E', 'L', 'F', 1, 0, 0, 0}
	if _, err := tempFile.Write(elfHeader); err != nil {
		t.Fatal(err)
	}
	tempFile.Close()

	arch = scanner.detectArchitecture(tempFile.Name())
	if arch != "x86" {
		t.Errorf("Expected 'x86' for 32-bit ELF, got %s", arch)
	}
}

func TestServiceScannerParseServiceFile(t *testing.T) {
	scanner := NewServiceScanner()

	// Test with non-existent file
	_, err := scanner.parseServiceFile("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Create a temporary service file
	tempFile, err := os.CreateTemp("", testServiceName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	content := `[Unit]
Description=Test
[Service]
Type=simple
`
	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tempFile.Close()

	metadata, err := scanner.parseServiceFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if desc, ok := metadata["description"]; !ok || desc != "Test" {
		t.Errorf("Expected description 'Test', got %s", desc)
	}

	if serviceType, ok := metadata["service_type"]; !ok || serviceType != "simple" {
		t.Errorf("Expected service_type 'simple', got %s", serviceType)
	}
}
