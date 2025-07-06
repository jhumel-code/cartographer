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

// Test constants for CycloneDX package manager files
const (
	// CycloneDX file names
	cycloneDxPackageJSON     = "package.json"
	cycloneDxPackageLock     = "package-lock.json"
	cycloneDxYarnLock        = "yarn.lock"
	cycloneDxPnpmLock        = "pnpm-lock.yaml"
	cycloneDxNpmShrinkwrap   = "npm-shrinkwrap.json"
	cycloneDxBowerJSON       = "bower.json"
	cycloneDxPyprojectToml   = "pyproject.toml"
	cycloneDxRequirementsTxt = "requirements.txt"
	cycloneDxSetupPy         = "setup.py"
	cycloneDxPipfile         = "Pipfile"
	cycloneDxPipfileLock     = "Pipfile.lock"
	cycloneDxPoetryLock      = "poetry.lock"
	cycloneDxPomXML          = "pom.xml"
	cycloneDxBuildGradle     = "build.gradle"
	cycloneDxGoMod           = "go.mod"
	cycloneDxGoSum           = "go.sum"
	cycloneDxCargoToml       = "Cargo.toml"
	cycloneDxCargoLock       = "Cargo.lock"
	cycloneDxGemfile         = "Gemfile"
	cycloneDxGemfileLock     = "Gemfile.lock"
	cycloneDxComposerJSON    = "composer.json"
	cycloneDxComposerLock    = "composer.lock"
	cycloneDxPodfile         = "Podfile"
	cycloneDxPodfileLock     = "Podfile.lock"
)

// CycloneDX package manager file contents
var (
	packageJSONContent = `{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}`

	requirementsTxtContent = `Django==4.2.0
requests>=2.28.0
pytest==7.4.0`

	pomXMLContent = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
</project>`

	buildGradleContent = `plugins {
    id 'java'
}

dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
}`

	goModContent = `module github.com/example/test-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/go-redis/redis/v8 v8.11.5
)`

	cargoTomlContent = `[package]
name = "test-app"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = "1.0"`

	gemfileContent = `source 'https://rubygems.org'

gem 'rails', '~> 7.0.0'
gem 'pg', '~> 1.1'
gem 'puma', '~> 5.0'`

	composerJSONContent = `{
    "name": "example/test-app",
    "require": {
        "symfony/console": "^6.0",
        "doctrine/orm": "^2.12"
    }
}`
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
		// Original types
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
		// CycloneDX Package Manager Files
		artifact.TypePackageJSON,
		artifact.TypePackageLock,
		artifact.TypeYarnLock,
		artifact.TypePnpmLock,
		artifact.TypeNpmShrinkwrap,
		artifact.TypeBowerJSON,
		artifact.TypePyprojectToml,
		artifact.TypeRequirementsTxt,
		artifact.TypeSetupPy,
		artifact.TypePipfile,
		artifact.TypePipfileLock,
		artifact.TypePoetryLock,
		artifact.TypePdmLock,
		artifact.TypeUvLock,
		artifact.TypePomXML,
		artifact.TypeBuildGradle,
		artifact.TypeGoMod,
		artifact.TypeGoSum,
		artifact.TypeCargoToml,
		artifact.TypeCargoLock,
		artifact.TypeGemfile,
		artifact.TypeGemfileLock,
		artifact.TypeComposerJSON,
		artifact.TypeComposerLock,
		artifact.TypePodfile,
		artifact.TypePodfileLock,
		artifact.TypePackageSwift,
		artifact.TypePackageResolved,
		artifact.TypeProjectClj,
		artifact.TypeDepsEdn,
		artifact.TypeCabalProject,
		artifact.TypeCabalFreeze,
		artifact.TypeMixExs,
		artifact.TypeMixLock,
		artifact.TypeConanfile,
		artifact.TypeConanLock,
		artifact.TypePubspecYaml,
		artifact.TypePubspecLock,
		artifact.TypeProjectAssets,
		artifact.TypePackagesLock,
		artifact.TypePackagesConfig,
		artifact.TypePaketLock,
		artifact.TypeCsprojFile,
		artifact.TypeVbprojFile,
		artifact.TypeFsprojFile,
		artifact.TypeSlnFile,
		artifact.TypeNugetPackage,
		artifact.TypeGopkgLock,
		artifact.TypeGopkgToml,
		artifact.TypeGemspec,
		artifact.TypeJarFile,
		artifact.TypeWarFile,
		artifact.TypeEarFile,
		artifact.TypeWheelFile,
		artifact.TypeEggFile,
		artifact.TypeApkFile,
		artifact.TypeAabFile,
		artifact.TypeHpiFile,
		artifact.TypeCMakeFile,
		artifact.TypeMesonBuild,
		artifact.TypeBazelFile,
		artifact.TypeBuildMill,
		artifact.TypeSbtFile,
		artifact.TypeGradleWrapper,
		artifact.TypeHelmValues,
		artifact.TypeHelmChartYaml,
		artifact.TypeOsqueryConf,
		artifact.TypeOpenAPISpec,
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
		"uid":       "1000",
		"gid":       "1000",
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

func TestTarLayerScannerCycloneDXPackages(t *testing.T) {
	scanner := NewTarLayerScanner()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/test/cyclonedx",
	}

	// Create test tar archive with CycloneDX package manager files
	files := map[string]TarFileInfo{
		"package.json": {
			Content: packageJSONContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"requirements.txt": {
			Content: requirementsTxtContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"pom.xml": {
			Content: pomXMLContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"build.gradle": {
			Content: buildGradleContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"go.mod": {
			Content: goModContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"Cargo.toml": {
			Content: cargoTomlContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"Gemfile": {
			Content: gemfileContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"composer.json": {
			Content: composerJSONContent,
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"test-app.jar": {
			Content: "", // JAR content doesn't matter for detection
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"app.war": {
			Content: "", // WAR content doesn't matter for detection
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"dist/package-1.0.0.whl": {
			Content: "", // Wheel content doesn't matter for detection
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
		"CMakeLists.txt": {
			Content: "cmake_minimum_required(VERSION 3.10)\nproject(TestApp)",
			Mode:    0644,
			Uid:     1000,
			Gid:     1000,
			Uname:   "user",
			Gname:   "user",
		},
	}

	tarBuffer := createTestTarArchive(files)
	ctx := context.Background()

	artifacts, err := scanner.ScanLayer(ctx, tarBuffer, source)

	if err != nil {
		t.Fatalf("ScanLayer() error = %v", err)
	}

	// Verify we found CycloneDX package artifacts
	if len(artifacts) == 0 {
		t.Fatal("ScanLayer() found no CycloneDX package artifacts")
	}

	// Test specific CycloneDX artifact types
	typeMap := make(map[artifact.Type]int)
	for _, art := range artifacts {
		typeMap[art.Type]++
	}

	// Check that we detected various CycloneDX package types
	expectedCycloneDXTypes := map[artifact.Type]int{
		artifact.TypePackageJSON:     1, // package.json
		artifact.TypeRequirementsTxt: 1, // requirements.txt
		artifact.TypePomXML:          1, // pom.xml
		artifact.TypeBuildGradle:     1, // build.gradle
		artifact.TypeGoMod:           1, // go.mod
		artifact.TypeCargoToml:       1, // Cargo.toml
		artifact.TypeGemfile:         1, // Gemfile
		artifact.TypeComposerJSON:    1, // composer.json
		artifact.TypeJarFile:         1, // test-app.jar
		artifact.TypeWarFile:         1, // app.war
		artifact.TypeWheelFile:       1, // package-1.0.0.whl
		artifact.TypeCMakeFile:       1, // CMakeLists.txt
	}

	for expectedType, expectedCount := range expectedCycloneDXTypes {
		if actualCount := typeMap[expectedType]; actualCount != expectedCount {
			t.Errorf("Expected %d artifacts of type %s, got %d", expectedCount, expectedType, actualCount)
		}
	}

	// Verify specific artifact properties
	for _, art := range artifacts {
		switch art.Type {
		case artifact.TypePackageJSON:
			if art.Name != "package.json" {
				t.Errorf("PackageJSON artifact name = %v, expected package.json", art.Name)
			}
		case artifact.TypeRequirementsTxt:
			if art.Name != "requirements.txt" {
				t.Errorf("RequirementsTxt artifact name = %v, expected requirements.txt", art.Name)
			}
		case artifact.TypePomXML:
			if art.Name != "pom.xml" {
				t.Errorf("PomXML artifact name = %v, expected pom.xml", art.Name)
			}
		case artifact.TypeJarFile:
			if art.Name != "test-app.jar" {
				t.Errorf("JarFile artifact name = %v, expected test-app.jar", art.Name)
			}
		}
	}
}

func TestTarLayerScannerDetectPackageManagerFile(t *testing.T) {
	scanner := NewTarLayerScanner()

	tests := []struct {
		name         string
		fileName     string
		filePath     string
		expectedType string
	}{
		// Node.js ecosystem
		{
			name:         "package.json",
			fileName:     "package.json",
			filePath:     "package.json",
			expectedType: string(artifact.TypePackageJSON),
		},
		{
			name:         "package-lock.json",
			fileName:     "package-lock.json",
			filePath:     "package-lock.json",
			expectedType: string(artifact.TypePackageLock),
		},
		{
			name:         "yarn.lock",
			fileName:     "yarn.lock",
			filePath:     "yarn.lock",
			expectedType: string(artifact.TypeYarnLock),
		},
		// Python ecosystem
		{
			name:         "requirements.txt",
			fileName:     "requirements.txt",
			filePath:     "requirements.txt",
			expectedType: string(artifact.TypeRequirementsTxt),
		},
		{
			name:         "pyproject.toml",
			fileName:     "pyproject.toml",
			filePath:     "pyproject.toml",
			expectedType: string(artifact.TypePyprojectToml),
		},
		{
			name:         "setup.py",
			fileName:     "setup.py",
			filePath:     "setup.py",
			expectedType: string(artifact.TypeSetupPy),
		},
		// Java ecosystem
		{
			name:         "pom.xml",
			fileName:     "pom.xml",
			filePath:     "pom.xml",
			expectedType: string(artifact.TypePomXML),
		},
		{
			name:         "build.gradle",
			fileName:     "build.gradle",
			filePath:     "build.gradle",
			expectedType: string(artifact.TypeBuildGradle),
		},
		{
			name:         "JAR file",
			fileName:     "test-app.jar",
			filePath:     "target/test-app.jar",
			expectedType: string(artifact.TypeJarFile),
		},
		// Go ecosystem
		{
			name:         "go.mod",
			fileName:     "go.mod",
			filePath:     "go.mod",
			expectedType: string(artifact.TypeGoMod),
		},
		{
			name:         "go.sum",
			fileName:     "go.sum",
			filePath:     "go.sum",
			expectedType: string(artifact.TypeGoSum),
		},
		// Rust ecosystem
		{
			name:         "Cargo.toml",
			fileName:     "Cargo.toml",
			filePath:     "Cargo.toml",
			expectedType: string(artifact.TypeCargoToml),
		},
		{
			name:         "Cargo.lock",
			fileName:     "Cargo.lock",
			filePath:     "Cargo.lock",
			expectedType: string(artifact.TypeCargoLock),
		},
		// Ruby ecosystem
		{
			name:         "Gemfile",
			fileName:     "Gemfile",
			filePath:     "Gemfile",
			expectedType: string(artifact.TypeGemfile),
		},
		{
			name:         "Gemfile.lock",
			fileName:     "Gemfile.lock",
			filePath:     "Gemfile.lock",
			expectedType: string(artifact.TypeGemfileLock),
		},
		// PHP ecosystem
		{
			name:         "composer.json",
			fileName:     "composer.json",
			filePath:     "composer.json",
			expectedType: string(artifact.TypeComposerJSON),
		},
		{
			name:         "composer.lock",
			fileName:     "composer.lock",
			filePath:     "composer.lock",
			expectedType: string(artifact.TypeComposerLock),
		},
		// Build systems
		{
			name:         "CMakeLists.txt",
			fileName:     "CMakeLists.txt",
			filePath:     "CMakeLists.txt",
			expectedType: string(artifact.TypeCMakeFile),
		},
		{
			name:         "meson.build",
			fileName:     "meson.build",
			filePath:     "meson.build",
			expectedType: string(artifact.TypeMesonBuild),
		},
		// Docker and container files
		{
			name:         "Dockerfile",
			fileName:     "Dockerfile",
			filePath:     "Dockerfile",
			expectedType: "",
		},
		// Helm
		{
			name:         "Chart.yaml",
			fileName:     "Chart.yaml",
			filePath:     "Chart.yaml",
			expectedType: string(artifact.TypeHelmChartYaml),
		},
		{
			name:         "values.yaml in helm chart",
			fileName:     "values.yaml",
			filePath:     "helm/charts/myapp/values.yaml",
			expectedType: string(artifact.TypeHelmValues),
		},
		{
			name:         "values.yaml not in helm chart",
			fileName:     "values.yaml",
			filePath:     "config/values.yaml",
			expectedType: "",
		},
		// Unknown file
		{
			name:         "unknown file",
			fileName:     "unknown.xyz",
			filePath:     "unknown.xyz",
			expectedType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectPackageManagerFile(tt.fileName, tt.filePath)
			if result != tt.expectedType {
				t.Errorf("detectPackageManagerFile() = %v, expected %v", result, tt.expectedType)
			}
		})
	}
}
