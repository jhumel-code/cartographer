package scanner

import (
	"archive/tar"
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// TarLayerScanner scans Docker layer tar streams
type TarLayerScanner struct{}

// NewTarLayerScanner creates a new tar layer scanner
func NewTarLayerScanner() *TarLayerScanner {
	return &TarLayerScanner{}
}

// Name returns the scanner name
func (s *TarLayerScanner) Name() string {
	return "tar-layer-scanner"
}

// SupportedTypes returns the types this scanner can detect
func (s *TarLayerScanner) SupportedTypes() []artifact.Type {
	return []artifact.Type{
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
}

// Scan scans a tar stream (not implemented for regular scanning)
func (s *TarLayerScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return nil, nil // This scanner only works with layer content
}

// ScanLayer implements LayerScanner interface
func (s *TarLayerScanner) ScanLayer(ctx context.Context, content io.Reader, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	tarReader := tar.NewReader(content)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip problematic entries
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Create artifact based on file type
		if artifact := s.analyzeFile(header, source); artifact != nil {
			artifacts = append(artifacts, *artifact)
		}

		// Special handling for dpkg status file
		if header.Name == "var/lib/dpkg/status" {
			dpkgArtifacts := s.scanDpkgStatus(tarReader, source)
			artifacts = append(artifacts, dpkgArtifacts...)
		}
	}

	return artifacts, nil
}

// analyzeFile analyzes a single file from the tar
func (s *TarLayerScanner) analyzeFile(header *tar.Header, source artifact.Source) *artifact.Artifact {
	fileName := filepath.Base(header.Name)

	// Determine artifact type
	artifactType := s.determineArtifactType(header)
	if artifactType == "" {
		return nil
	}

	modTime := header.ModTime
	return &artifact.Artifact{
		Name:        fileName,
		Type:        artifact.Type(artifactType),
		Path:        header.Name,
		Source:      source,
		Size:        header.Size,
		Permissions: header.FileInfo().Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": artifactType,
			"uid":       string(rune(header.Uid)),
			"gid":       string(rune(header.Gid)),
			"uname":     header.Uname,
			"gname":     header.Gname,
		},
	}
}

// determineArtifactType determines the type of artifact
func (s *TarLayerScanner) determineArtifactType(header *tar.Header) string {
	fileName := filepath.Base(header.Name)
	ext := filepath.Ext(fileName)
	filePath := header.Name

	// Check for libraries first
	if ext == ".so" || strings.Contains(fileName, ".so.") {
		return string(artifact.TypeSharedLibrary)
	}
	if ext == ".a" {
		return string(artifact.TypeStaticLibrary)
	}

	// Check for scripts by shebang or extension
	if strings.HasSuffix(fileName, ".sh") || strings.HasSuffix(fileName, ".bash") {
		return string(artifact.TypeShellScript)
	}
	if strings.HasSuffix(fileName, ".py") {
		return string(artifact.TypePythonScript)
	}

	// Check for executables (files in common executable directories with execute permission)
	if header.Mode&0111 != 0 { // Has execute permission
		if strings.HasPrefix(filePath, "bin/") ||
			strings.HasPrefix(filePath, "usr/bin/") ||
			strings.HasPrefix(filePath, "usr/local/bin/") ||
			strings.HasPrefix(filePath, "sbin/") ||
			strings.HasPrefix(filePath, "usr/sbin/") ||
			strings.HasPrefix(filePath, "opt/") {
			return string(artifact.TypeExecutable)
		}
	}

	// Check for security files
	if strings.HasSuffix(fileName, ".pem") || strings.HasSuffix(fileName, ".crt") || strings.HasSuffix(fileName, ".cer") {
		return string(artifact.TypeCertificate)
	}
	if strings.HasSuffix(fileName, ".key") && !strings.Contains(filePath, "apt") {
		return string(artifact.TypePrivateKey)
	}
	if strings.HasSuffix(fileName, ".pub") {
		return string(artifact.TypePublicKey)
	}

	// Check for system configuration files
	if strings.HasSuffix(fileName, ".service") || strings.HasSuffix(fileName, ".socket") || strings.HasSuffix(fileName, ".timer") {
		if strings.Contains(filePath, "systemd") {
			return string(artifact.TypeSystemdUnit)
		}
	}

	// Check for environment files
	if strings.HasPrefix(fileName, ".env") || fileName == "environment" {
		return string(artifact.TypeEnvironmentFile)
	}

	// Check for cron jobs
	if strings.Contains(filePath, "cron") && (strings.Contains(filePath, "daily") || strings.Contains(filePath, "weekly") || strings.Contains(filePath, "monthly")) {
		return string(artifact.TypeCronJob)
	}

	// Check for configuration files
	configPatterns := []string{
		".conf", ".config", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".properties",
	}

	for _, pattern := range configPatterns {
		if strings.HasSuffix(fileName, pattern) {
			return string(artifact.TypeConfigFile)
		}
	}

	// Check for specific config files
	configFiles := []string{
		"nginx.conf", "apache2.conf", "httpd.conf", "my.cnf", "postgresql.conf",
		"sshd_config", "ssh_config", "sudoers", "hosts", "passwd", "group",
		"shadow", "fstab", "resolv.conf", "nsswitch.conf",
	}

	for _, configFile := range configFiles {
		if fileName == configFile {
			return string(artifact.TypeConfigFile)
		}
	}

	return ""
}

// scanDpkgStatus scans the dpkg status file for installed packages
func (s *TarLayerScanner) scanDpkgStatus(reader io.Reader, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// Read the entire status file content
	content, err := io.ReadAll(reader)
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(content), "\n")
	var currentPackage *artifact.Artifact

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			// End of package entry
			if currentPackage != nil {
				artifacts = append(artifacts, *currentPackage)
				currentPackage = nil
			}
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			name := strings.TrimPrefix(line, "Package: ")
			currentPackage = &artifact.Artifact{
				Name:   name,
				Type:   artifact.TypeDebianPackage,
				Path:   "var/lib/dpkg/status",
				Source: source,
				Metadata: map[string]string{
					"package_manager": "dpkg",
				},
			}
		} else if currentPackage != nil {
			if strings.HasPrefix(line, "Version: ") {
				currentPackage.Version = strings.TrimPrefix(line, "Version: ")
			} else if strings.HasPrefix(line, "Description: ") {
				currentPackage.Metadata["description"] = strings.TrimPrefix(line, "Description: ")
			} else if strings.HasPrefix(line, "Architecture: ") {
				currentPackage.Metadata["architecture"] = strings.TrimPrefix(line, "Architecture: ")
			} else if strings.HasPrefix(line, "Status: ") {
				currentPackage.Metadata["status"] = strings.TrimPrefix(line, "Status: ")
			}
		}
	}

	// Handle last package if file doesn't end with empty line
	if currentPackage != nil {
		artifacts = append(artifacts, *currentPackage)
	}

	return artifacts
}
