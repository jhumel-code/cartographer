package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// Test constants for layer scanner tests
const (
	// File names
	layerExecutableFile   = "test-binary"
	layerSharedLibFile    = "libtest.so.1"
	layerStaticLibFile    = "libtest.a"
	layerShellScriptFile  = "script.sh"
	layerPythonScriptFile = "script.py"
	layerConfigFile       = "config.conf"
	layerEnvFile          = ".env"
	layerCertFile         = "cert.pem"
	layerPrivateKeyFile   = "private.key"
	layerPublicKeyFile    = "public.pub"
	layerSystemdUnitFile  = "service.service"
	layerCronJobFile      = "daily-backup"
	layerDpkgStatusFile   = "var/lib/dpkg/status"

	// File contents
	shellScriptContent = `#!/bin/bash
echo "Hello World"`

	pythonScriptContent = `#!/usr/bin/env python3
print("Hello World")`

	configFileContent = `[section]
key=value
debug=true`

	envFileContent = `PATH=/usr/bin:/bin
HOME=/root
DEBUG=true`

	certFileContent = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7VJTUt9Us8cKB
-----END CERTIFICATE-----`

	privateKeyContent = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
UjFFVQc+OQTB6tA+CBmhUEfK8FH6rz7o6z4EJzQ1LbQJKjmQz4mTXYXzM6wRsM5B
-----END PRIVATE KEY-----`

	publicKeyContent = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7VJTUt9Us8cKBUjFFVQc+OQTB6tA+CBmhUEfK8FH6rz7o6z4EJzQ1LbQJKjmQz4mTXYXzM6wRsM5B user@host`

	systemdUnitContent = `[Unit]
Description=Test Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/test-daemon
Restart=always

[Install]
WantedBy=multi-user.target`

	dpkgStatusContent = `Package: curl
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 411
Maintainer: Ubuntu Developers
Architecture: amd64
Multi-Arch: foreign
Version: 7.68.0-1ubuntu2.18
Description: command line tool for transferring data with URL syntax

Package: vim
Status: install ok installed
Priority: optional
Section: editors
Installed-Size: 3203
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 2:8.1.2269-1ubuntu5.15
Description: Vi IMproved - enhanced vi editor

Package: git
Status: install ok installed
Priority: optional
Section: vcs
Installed-Size: 25948
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 1:2.25.1-1ubuntu3.10
Description: fast, scalable, distributed revision control system
`
)

// Helper function to create a tar archive with test files
func createTestTarArchive(files map[string]TarFileInfo) *bytes.Buffer {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for path, info := range files {
		hdr := &tar.Header{
			Name:     path,
			Mode:     info.Mode,
			Size:     int64(len(info.Content)),
			ModTime:  time.Now(),
			Typeflag: tar.TypeReg,
			Uid:      info.Uid,
			Gid:      info.Gid,
			Uname:    info.Uname,
			Gname:    info.Gname,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}

		if _, err := tw.Write([]byte(info.Content)); err != nil {
			panic(err)
		}
	}

	tw.Close()
	return &buf
}

// TarFileInfo represents file information for creating test tar archives
type TarFileInfo struct {
	Content string
	Mode    int64
	Uid     int
	Gid     int
	Uname   string
	Gname   string
}

func TestNewTarLayerScanner(t *testing.T) {
	scanner := NewTarLayerScanner()
	if scanner == nil {
		t.Fatal("NewTarLayerScanner() returned nil")
	}
}

func TestTarLayerScannerName(t *testing.T) {
	scanner := NewTarLayerScanner()
	expected := "tar-layer-scanner"
	if scanner.Name() != expected {
		t.Errorf("Name() = %v, want %v", scanner.Name(), expected)
	}
}

func TestTarLayerScannerSupportedTypes(t *testing.T) {
	scanner := NewTarLayerScanner()
	types := scanner.SupportedTypes()

	expectedTypes := []artifact.Type{
		artifact.TypeExecutable,
		artifact.TypeSharedLibrary,
		artifact.TypeStaticLibrary,
		artifact.TypeConfigFile,
		artifact.TypeEnvironmentFile,
		artifact.TypeSystemdUnit,
		artifact.TypeCronJob,
		artifact.TypeDebianPackage,
		artifact.TypeRPMPackage,
		artifact.TypeAlpinePackage,
		artifact.TypeShellScript,
		artifact.TypePythonScript,
		artifact.TypeCertificate,
		artifact.TypePrivateKey,
		artifact.TypePublicKey,
	}

	if len(types) != len(expectedTypes) {
		t.Errorf("SupportedTypes() returned %d types, expected %d", len(types), len(expectedTypes))
	}

	for _, expectedType := range expectedTypes {
		found := false
		for _, actualType := range types {
			if actualType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedTypes() missing expected type: %s", expectedType)
		}
	}
}

func TestTarLayerScannerScan(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	ctx := context.Background()
	artifacts, err := scanner.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, expected nil", err)
	}

	if artifacts != nil {
		t.Errorf("Scan() returned %v, expected nil", artifacts)
	}
}

func TestTarLayerScannerScanLayer(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test/layer",
	}

	// Create test tar archive with various file types
	files := map[string]TarFileInfo{
		"usr/bin/curl": {
			Content: "", // Binary content doesn't matter for this test
			Mode:    0755,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"usr/lib/x86_64-linux-gnu/libcurl.so.4": {
			Content: "", // Binary content
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"usr/lib/x86_64-linux-gnu/libstatic.a": {
			Content: "", // Static library content
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"home/user/script.sh": {
			Content: shellScriptContent,
			Mode:    0755,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"home/user/script.py": {
			Content: pythonScriptContent,
			Mode:    0755,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"etc/nginx/nginx.conf": {
			Content: configFileContent,
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"home/user/.env": {
			Content: envFileContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"etc/ssl/certs/server.pem": {
			Content: certFileContent,
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"etc/ssl/private/server.key": {
			Content: privateKeyContent,
			Mode:    0600,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"home/user/.ssh/id_rsa.pub": {
			Content: publicKeyContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"etc/systemd/system/myservice.service": {
			Content: systemdUnitContent,
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"etc/cron.daily/backup": {
			Content: shellScriptContent,
			Mode:    0755,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
		"var/lib/dpkg/status": {
			Content: dpkgStatusContent,
			Mode:    0644,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
		},
	}

	tarBuffer := createTestTarArchive(files)
	ctx := context.Background()

	artifacts, err := scanner.ScanLayer(ctx, tarBuffer, source)

	if err != nil {
		t.Fatalf("ScanLayer() error = %v", err)
	}

	// Verify we found artifacts
	if len(artifacts) == 0 {
		t.Fatal("ScanLayer() found no artifacts")
	}

	// Test specific artifact types
	typeMap := make(map[artifact.Type]int)
	for _, art := range artifacts {
		typeMap[art.Type]++
	}

	// Check that we detected various artifact types
	expectedCounts := map[artifact.Type]int{
		artifact.TypeExecutable:      1, // curl
		artifact.TypeSharedLibrary:   1, // libcurl.so.4
		artifact.TypeStaticLibrary:   1, // libstatic.a
		artifact.TypeShellScript:     1, // script.sh (backup is detected as cron job)
		artifact.TypePythonScript:    1, // script.py
		artifact.TypeConfigFile:      1, // nginx.conf
		artifact.TypeEnvironmentFile: 1, // .env
		artifact.TypeCertificate:     1, // server.pem
		artifact.TypePrivateKey:      1, // server.key
		artifact.TypePublicKey:       1, // id_rsa.pub
		artifact.TypeSystemdUnit:     1, // myservice.service
		artifact.TypeCronJob:         1, // backup
		artifact.TypeDebianPackage:   3, // curl, vim, git from dpkg/status
	}

	for expectedType, expectedCount := range expectedCounts {
		if actualCount := typeMap[expectedType]; actualCount != expectedCount {
			t.Errorf("Expected %d artifacts of type %s, got %d", expectedCount, expectedType, actualCount)
		}
	}
}

func TestTarLayerScannerAnalyzeFile(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	tests := []struct {
		name         string
		header       *tar.Header
		expectedType artifact.Type
		expectNil    bool
	}{
		{
			name: "executable file",
			header: &tar.Header{
				Name: "usr/bin/test",
				Mode: 0755,
				Size: 1024,
			},
			expectedType: artifact.TypeExecutable,
		},
		{
			name: "shared library",
			header: &tar.Header{
				Name: "usr/lib/libtest.so.1",
				Mode: 0644,
				Size: 2048,
			},
			expectedType: artifact.TypeSharedLibrary,
		},
		{
			name: "static library",
			header: &tar.Header{
				Name: "usr/lib/libtest.a",
				Mode: 0644,
				Size: 4096,
			},
			expectedType: artifact.TypeStaticLibrary,
		},
		{
			name: "shell script",
			header: &tar.Header{
				Name: "home/user/script.sh",
				Mode: 0755,
				Size: 100,
			},
			expectedType: artifact.TypeShellScript,
		},
		{
			name: "python script",
			header: &tar.Header{
				Name: "home/user/script.py",
				Mode: 0755,
				Size: 200,
			},
			expectedType: artifact.TypePythonScript,
		},
		{
			name: "config file",
			header: &tar.Header{
				Name: "etc/nginx.conf",
				Mode: 0644,
				Size: 512,
			},
			expectedType: artifact.TypeConfigFile,
		},
		{
			name: "certificate",
			header: &tar.Header{
				Name: "etc/ssl/cert.pem",
				Mode: 0644,
				Size: 1500,
			},
			expectedType: artifact.TypeCertificate,
		},
		{
			name: "private key",
			header: &tar.Header{
				Name: "etc/ssl/private.key",
				Mode: 0600,
				Size: 1700,
			},
			expectedType: artifact.TypePrivateKey,
		},
		{
			name: "public key",
			header: &tar.Header{
				Name: "home/user/.ssh/id_rsa.pub",
				Mode: 0644,
				Size: 400,
			},
			expectedType: artifact.TypePublicKey,
		},
		{
			name: "systemd service",
			header: &tar.Header{
				Name: "etc/systemd/system/test.service",
				Mode: 0644,
				Size: 300,
			},
			expectedType: artifact.TypeSystemdUnit,
		},
		{
			name: "environment file",
			header: &tar.Header{
				Name: "home/user/.env",
				Mode: 0644,
				Size: 100,
			},
			expectedType: artifact.TypeEnvironmentFile,
		},
		{
			name: "unknown file type",
			header: &tar.Header{
				Name: "some/random/file.xyz",
				Mode: 0644,
				Size: 50,
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set ModTime for the header
			tt.header.ModTime = time.Now()

			artifact := scanner.analyzeFile(tt.header, source)

			if tt.expectNil {
				if artifact != nil {
					t.Errorf("analyzeFile() = %v, expected nil", artifact)
				}
				return
			}

			if artifact == nil {
				t.Fatalf("analyzeFile() = nil, expected artifact")
			}

			if artifact.Type != tt.expectedType {
				t.Errorf("analyzeFile() type = %v, expected %v", artifact.Type, tt.expectedType)
			}

			// Verify artifact properties
			if artifact.Name != tt.header.Name[strings.LastIndex(tt.header.Name, "/")+1:] {
				t.Errorf("analyzeFile() name = %v, expected %v", artifact.Name, tt.header.Name[strings.LastIndex(tt.header.Name, "/")+1:])
			}

			if artifact.Path != tt.header.Name {
				t.Errorf("analyzeFile() path = %v, expected %v", artifact.Path, tt.header.Name)
			}

			if artifact.Size != tt.header.Size {
				t.Errorf("analyzeFile() size = %v, expected %v", artifact.Size, tt.header.Size)
			}
		})
	}
}

func TestTarLayerScannerDetermineArtifactType(t *testing.T) {
	scanner := NewTarLayerScanner()

	tests := []struct {
		name         string
		header       *tar.Header
		expectedType string
	}{
		{
			name: "shared library with .so extension",
			header: &tar.Header{
				Name: "usr/lib/libtest.so",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeSharedLibrary),
		},
		{
			name: "shared library with version",
			header: &tar.Header{
				Name: "usr/lib/libtest.so.1.2.3",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeSharedLibrary),
		},
		{
			name: "static library",
			header: &tar.Header{
				Name: "usr/lib/libtest.a",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeStaticLibrary),
		},
		{
			name: "shell script by extension",
			header: &tar.Header{
				Name: "home/user/script.sh",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeShellScript),
		},
		{
			name: "bash script",
			header: &tar.Header{
				Name: "home/user/script.bash",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeShellScript),
		},
		{
			name: "python script",
			header: &tar.Header{
				Name: "home/user/script.py",
				Mode: 0755,
			},
			expectedType: string(artifact.TypePythonScript),
		},
		{
			name: "executable in /bin",
			header: &tar.Header{
				Name: "bin/test",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeExecutable),
		},
		{
			name: "executable in /usr/bin",
			header: &tar.Header{
				Name: "usr/bin/test",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeExecutable),
		},
		{
			name: "executable in /sbin",
			header: &tar.Header{
				Name: "sbin/test",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeExecutable),
		},
		{
			name: "certificate .pem",
			header: &tar.Header{
				Name: "etc/ssl/cert.pem",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeCertificate),
		},
		{
			name: "certificate .crt",
			header: &tar.Header{
				Name: "etc/ssl/cert.crt",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeCertificate),
		},
		{
			name: "private key",
			header: &tar.Header{
				Name: "etc/ssl/private.key",
				Mode: 0600,
			},
			expectedType: string(artifact.TypePrivateKey),
		},
		{
			name: "public key",
			header: &tar.Header{
				Name: "home/user/.ssh/id_rsa.pub",
				Mode: 0644,
			},
			expectedType: string(artifact.TypePublicKey),
		},
		{
			name: "systemd service",
			header: &tar.Header{
				Name: "etc/systemd/system/test.service",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeSystemdUnit),
		},
		{
			name: "systemd socket",
			header: &tar.Header{
				Name: "etc/systemd/system/test.socket",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeSystemdUnit),
		},
		{
			name: "environment file .env",
			header: &tar.Header{
				Name: "home/user/.env",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeEnvironmentFile),
		},
		{
			name: "environment file named environment",
			header: &tar.Header{
				Name: "etc/environment",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeEnvironmentFile),
		},
		{
			name: "cron daily job",
			header: &tar.Header{
				Name: "etc/cron.daily/backup",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeCronJob),
		},
		{
			name: "cron weekly job",
			header: &tar.Header{
				Name: "etc/cron.weekly/maintenance",
				Mode: 0755,
			},
			expectedType: string(artifact.TypeCronJob),
		},
		{
			name: "config file .conf",
			header: &tar.Header{
				Name: "etc/nginx.conf",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeConfigFile),
		},
		{
			name: "config file .yaml",
			header: &tar.Header{
				Name: "etc/config.yaml",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeConfigFile),
		},
		{
			name: "specific config file",
			header: &tar.Header{
				Name: "etc/passwd",
				Mode: 0644,
			},
			expectedType: string(artifact.TypeConfigFile),
		},
		{
			name: "unknown file",
			header: &tar.Header{
				Name: "some/unknown/file.xyz",
				Mode: 0644,
			},
			expectedType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.determineArtifactType(tt.header)
			if result != tt.expectedType {
				t.Errorf("determineArtifactType() = %v, expected %v", result, tt.expectedType)
			}
		})
	}
}

func TestTarLayerScannerScanDpkgStatus(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	reader := strings.NewReader(dpkgStatusContent)
	artifacts := scanner.scanDpkgStatus(reader, source)

	// Should find 3 packages: curl, vim, git
	expectedPackages := []string{"curl", "vim", "git"}
	if len(artifacts) != len(expectedPackages) {
		t.Errorf("scanDpkgStatus() found %d packages, expected %d", len(artifacts), len(expectedPackages))
	}

	for i, expectedName := range expectedPackages {
		if i >= len(artifacts) {
			t.Errorf("Missing package: %s", expectedName)
			continue
		}

		art := artifacts[i]
		if art.Name != expectedName {
			t.Errorf("Package %d: name = %v, expected %v", i, art.Name, expectedName)
		}

		if art.Type != artifact.TypeDebianPackage {
			t.Errorf("Package %d: type = %v, expected %v", i, art.Type, artifact.TypeDebianPackage)
		}

		if art.Path != "var/lib/dpkg/status" {
			t.Errorf("Package %d: path = %v, expected var/lib/dpkg/status", i, art.Path)
		}

		// Check version is set
		if art.Version == "" {
			t.Errorf("Package %d: version is empty", i)
		}

		// Check metadata
		if art.Metadata["package_manager"] != "dpkg" {
			t.Errorf("Package %d: package_manager = %v, expected dpkg", i, art.Metadata["package_manager"])
		}
	}

	// Test specific package details
	curlPackage := artifacts[0]
	if curlPackage.Version != "7.68.0-1ubuntu2.18" {
		t.Errorf("curl version = %v, expected 7.68.0-1ubuntu2.18", curlPackage.Version)
	}
	if curlPackage.Metadata["architecture"] != "amd64" {
		t.Errorf("curl architecture = %v, expected amd64", curlPackage.Metadata["architecture"])
	}
}

func TestTarLayerScannerScanLayerEmptyTar(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	// Create empty tar archive
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.Close()

	ctx := context.Background()
	artifacts, err := scanner.ScanLayer(ctx, &buf, source)

	if err != nil {
		t.Errorf("ScanLayer() error = %v, expected nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("ScanLayer() found %d artifacts in empty tar, expected 0", len(artifacts))
	}
}

func TestTarLayerScannerScanLayerWithDirectories(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	// Create tar archive with directories and files
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add directory
	dirHdr := &tar.Header{
		Name:     "usr/bin/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	tw.WriteHeader(dirHdr)

	// Add file
	fileHdr := &tar.Header{
		Name:     "usr/bin/test",
		Mode:     0755,
		Size:     0,
		Typeflag: tar.TypeReg,
		ModTime:  time.Now(),
	}
	tw.WriteHeader(fileHdr)
	tw.Write([]byte(""))

	tw.Close()

	ctx := context.Background()
	artifacts, err := scanner.ScanLayer(ctx, &buf, source)

	if err != nil {
		t.Errorf("ScanLayer() error = %v, expected nil", err)
	}

	// Should only find the file, not the directory
	if len(artifacts) != 1 {
		t.Errorf("ScanLayer() found %d artifacts, expected 1", len(artifacts))
	}

	if len(artifacts) > 0 && artifacts[0].Name != "test" {
		t.Errorf("ScanLayer() found artifact %v, expected test", artifacts[0].Name)
	}
}

func TestTarLayerScannerScanLayerCorruptedTar(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	// Create a tar archive with one valid header followed by corrupted data
	// This simulates a more realistic corruption scenario
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add one valid file
	hdr := &tar.Header{
		Name:    "test.txt",
		Mode:    0644,
		Size:    5,
		ModTime: time.Now(),
	}
	tw.WriteHeader(hdr)
	tw.Write([]byte("hello"))

	// Close the writer properly but then append corrupted data
	tw.Close()

	// Append some corrupted data that would break subsequent reads
	buf.Write([]byte("corrupted tar data that should not parse"))

	ctx := context.Background()
	artifacts, err := scanner.ScanLayer(ctx, &buf, source)

	// Should handle gracefully - either return error or just process the valid parts
	if err != nil {
		t.Logf("ScanLayer() returned error for partially corrupted data: %v", err)
	}

	// Should at least find the valid file before corruption
	if len(artifacts) == 0 {
		t.Log("ScanLayer() found no artifacts from partially corrupted tar")
	} else {
		t.Logf("ScanLayer() found %d artifacts from partially corrupted tar", len(artifacts))
		if artifacts[0].Name != "test.txt" {
			t.Errorf("Expected first artifact to be test.txt, got %s", artifacts[0].Name)
		}
	}
}

func TestTarLayerScannerMetadata(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test",
	}

	header := &tar.Header{
		Name:    "usr/bin/test",
		Mode:    0755,
		Size:    1024,
		Uid:     1000,
		Gid:     1000,
		Uname:   "testuser",
		Gname:   "testgroup",
		ModTime: time.Now(),
	}

	art := scanner.analyzeFile(header, source)

	if art == nil {
		t.Fatal("analyzeFile() returned nil")
	}

	// Check metadata
	expectedMetadata := map[string]string{
		"file_type": string(artifact.TypeExecutable),
		"uid":       string(rune(1000)),
		"gid":       string(rune(1000)),
		"uname":     "testuser",
		"gname":     "testgroup",
	}

	for key, expectedValue := range expectedMetadata {
		if actualValue, exists := art.Metadata[key]; !exists {
			t.Errorf("Metadata missing key: %s", key)
		} else if actualValue != expectedValue {
			t.Errorf("Metadata[%s] = %v, expected %v", key, actualValue, expectedValue)
		}
	}
}
