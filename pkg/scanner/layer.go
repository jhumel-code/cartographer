package scanner

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
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
		ID:          s.generateArtifactID(header.Name, source),
		Name:        fileName,
		Type:        artifact.Type(artifactType),
		Path:        header.Name,
		Source:      source,
		Size:        header.Size,
		Permissions: header.FileInfo().Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": artifactType,
			"uid":       fmt.Sprintf("%d", header.Uid),
			"gid":       fmt.Sprintf("%d", header.Gid),
			"uname":     header.Uname,
			"gname":     header.Gname,
		},
	}
}

// generateArtifactID creates a unique ID for an artifact
func (s *TarLayerScanner) generateArtifactID(path string, source artifact.Source) string {
	// Create a unique ID based on source location and path
	data := fmt.Sprintf("%s:%s", source.Location, path)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes of hash for ID
}

// determineArtifactType determines the type of artifact
func (s *TarLayerScanner) determineArtifactType(header *tar.Header) string {
	fileName := filepath.Base(header.Name)
	ext := filepath.Ext(fileName)
	filePath := header.Name

	// Check for CycloneDX package manager files first
	if packageType := s.detectPackageManagerFile(fileName, filePath); packageType != "" {
		return packageType
	}

	// Check for libraries
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
		if s.isExecutablePath(filePath) {
			return string(artifact.TypeExecutable)
		}
	}

	// Check for security files
	if s.isSecurityFile(fileName, filePath) {
		return s.getSecurityFileType(fileName, filePath)
	}

	// Check for system configuration files
	if s.isSystemFile(fileName, filePath) {
		return s.getSystemFileType(fileName, filePath)
	}

	// Check for configuration files
	if s.isConfigFile(fileName) {
		return string(artifact.TypeConfigFile)
	}

	return ""
}

// detectPackageManagerFile detects CycloneDX package manager files
func (s *TarLayerScanner) detectPackageManagerFile(fileName, filePath string) string {
	// Check for specific package manager files by name
	if packageType := s.detectByFileName(fileName); packageType != "" {
		return packageType
	}

	// Check for files by extension
	if packageType := s.detectByFileExtension(fileName); packageType != "" {
		return packageType
	}

	// Check for special path-based detection
	if packageType := s.detectByFilePath(fileName, filePath); packageType != "" {
		return packageType
	}

	return ""
}

// detectByFileName detects package files by exact filename match
func (s *TarLayerScanner) detectByFileName(fileName string) string {
	nodeJSFiles := map[string]string{
		"package.json":        string(artifact.TypePackageJSON),
		"package-lock.json":   string(artifact.TypePackageLock),
		"yarn.lock":           string(artifact.TypeYarnLock),
		"pnpm-lock.yaml":      string(artifact.TypePnpmLock),
		"npm-shrinkwrap.json": string(artifact.TypeNpmShrinkwrap),
		"bower.json":          string(artifact.TypeBowerJSON),
	}

	pythonFiles := map[string]string{
		"pyproject.toml":   string(artifact.TypePyprojectToml),
		"requirements.txt": string(artifact.TypeRequirementsTxt),
		"setup.py":         string(artifact.TypeSetupPy),
		"Pipfile":          string(artifact.TypePipfile),
		"Pipfile.lock":     string(artifact.TypePipfileLock),
		"poetry.lock":      string(artifact.TypePoetryLock),
		"pdm.lock":         string(artifact.TypePdmLock),
		"uv.lock":          string(artifact.TypeUvLock),
	}

	javaFiles := map[string]string{
		"pom.xml":      string(artifact.TypePomXML),
		"build.gradle": string(artifact.TypeBuildGradle),
	}

	goFiles := map[string]string{
		"go.mod":     string(artifact.TypeGoMod),
		"go.sum":     string(artifact.TypeGoSum),
		"Gopkg.lock": string(artifact.TypeGopkgLock),
		"Gopkg.toml": string(artifact.TypeGopkgToml),
	}

	rustFiles := map[string]string{
		"Cargo.toml": string(artifact.TypeCargoToml),
		"Cargo.lock": string(artifact.TypeCargoLock),
	}

	rubyFiles := map[string]string{
		"Gemfile":      string(artifact.TypeGemfile),
		"Gemfile.lock": string(artifact.TypeGemfileLock),
	}

	phpFiles := map[string]string{
		"composer.json": string(artifact.TypeComposerJSON),
		"composer.lock": string(artifact.TypeComposerLock),
	}

	allFiles := make(map[string]string)
	for k, v := range nodeJSFiles {
		allFiles[k] = v
	}
	for k, v := range pythonFiles {
		allFiles[k] = v
	}
	for k, v := range javaFiles {
		allFiles[k] = v
	}
	for k, v := range goFiles {
		allFiles[k] = v
	}
	for k, v := range rustFiles {
		allFiles[k] = v
	}
	for k, v := range rubyFiles {
		allFiles[k] = v
	}
	for k, v := range phpFiles {
		allFiles[k] = v
	}

	// Add other ecosystem files
	otherFiles := map[string]string{
		"Podfile":              string(artifact.TypePodfile),
		"Podfile.lock":         string(artifact.TypePodfileLock),
		"Package.swift":        string(artifact.TypePackageSwift),
		"Package.resolved":     string(artifact.TypePackageResolved),
		"project.clj":          string(artifact.TypeProjectClj),
		"deps.edn":             string(artifact.TypeDepsEdn),
		"cabal.project":        string(artifact.TypeCabalProject),
		"cabal.project.freeze": string(artifact.TypeCabalFreeze),
		"mix.exs":              string(artifact.TypeMixExs),
		"mix.lock":             string(artifact.TypeMixLock),
		"conanfile.txt":        string(artifact.TypeConanfile),
		"conanfile.py":         string(artifact.TypeConanfile),
		"conan.lock":           string(artifact.TypeConanLock),
		"pubspec.yaml":         string(artifact.TypePubspecYaml),
		"pubspec.lock":         string(artifact.TypePubspecLock),
		"project.assets.json":  string(artifact.TypeProjectAssets),
		"packages.lock.json":   string(artifact.TypePackagesLock),
		"packages.config":      string(artifact.TypePackagesConfig),
		"paket.lock":           string(artifact.TypePaketLock),
		"CMakeLists.txt":       string(artifact.TypeCMakeFile),
		"meson.build":          string(artifact.TypeMesonBuild),
		"BUILD":                string(artifact.TypeBazelFile),
		"BUILD.bazel":          string(artifact.TypeBazelFile),
		"build.mill":           string(artifact.TypeBuildMill),
		"Chart.yaml":           string(artifact.TypeHelmChartYaml),
		"openapi.json":         string(artifact.TypeOpenAPISpec),
		"openapi.yaml":         string(artifact.TypeOpenAPISpec),
		"swagger.json":         string(artifact.TypeOpenAPISpec),
		"swagger.yaml":         string(artifact.TypeOpenAPISpec),
	}

	for k, v := range otherFiles {
		allFiles[k] = v
	}

	return allFiles[fileName]
}

// detectByFileExtension detects package files by extension
func (s *TarLayerScanner) detectByFileExtension(fileName string) string {
	ext := filepath.Ext(fileName)
	extensionMap := map[string]string{
		".gemspec": string(artifact.TypeGemspec),
		".jar":     string(artifact.TypeJarFile),
		".war":     string(artifact.TypeWarFile),
		".ear":     string(artifact.TypeEarFile),
		".whl":     string(artifact.TypeWheelFile),
		".egg":     string(artifact.TypeEggFile),
		".apk":     string(artifact.TypeApkFile),
		".aab":     string(artifact.TypeAabFile),
		".hpi":     string(artifact.TypeHpiFile),
		".nupkg":   string(artifact.TypeNugetPackage),
		".csproj":  string(artifact.TypeCsprojFile),
		".vbproj":  string(artifact.TypeVbprojFile),
		".fsproj":  string(artifact.TypeFsprojFile),
		".sln":     string(artifact.TypeSlnFile),
		".sbt":     string(artifact.TypeSbtFile),
		".cmake":   string(artifact.TypeCMakeFile),
	}

	return extensionMap[ext]
}

// detectByFilePath detects package files by path patterns
func (s *TarLayerScanner) detectByFilePath(fileName, filePath string) string {
	// Check for Gradle wrapper files
	if strings.Contains(fileName, "gradlew") {
		return string(artifact.TypeGradleWrapper)
	}

	// Check for Helm values files
	if fileName == "values.yaml" && (strings.Contains(filePath, "helm") || strings.Contains(filePath, "chart")) {
		return string(artifact.TypeHelmValues)
	}

	return ""
}

// Helper methods for artifact type determination
func (s *TarLayerScanner) isExecutablePath(path string) bool {
	execPaths := []string{"bin/", "usr/bin/", "usr/local/bin/", "sbin/", "usr/sbin/", "opt/"}
	for _, execPath := range execPaths {
		if strings.HasPrefix(path, execPath) {
			return true
		}
	}
	return false
}

func (s *TarLayerScanner) isSecurityFile(fileName, filePath string) bool {
	return strings.HasSuffix(fileName, ".pem") ||
		strings.HasSuffix(fileName, ".crt") ||
		strings.HasSuffix(fileName, ".cer") ||
		(strings.HasSuffix(fileName, ".key") && !strings.Contains(filePath, "apt")) ||
		strings.HasSuffix(fileName, ".pub")
}

func (s *TarLayerScanner) getSecurityFileType(fileName, filePath string) string {
	if strings.HasSuffix(fileName, ".pem") || strings.HasSuffix(fileName, ".crt") || strings.HasSuffix(fileName, ".cer") {
		return string(artifact.TypeCertificate)
	}
	if strings.HasSuffix(fileName, ".key") && !strings.Contains(filePath, "apt") {
		return string(artifact.TypePrivateKey)
	}
	if strings.HasSuffix(fileName, ".pub") {
		return string(artifact.TypePublicKey)
	}
	return ""
}

func (s *TarLayerScanner) isSystemFile(fileName, filePath string) bool {
	return (strings.HasSuffix(fileName, ".service") || strings.HasSuffix(fileName, ".socket") || strings.HasSuffix(fileName, ".timer")) ||
		strings.HasPrefix(fileName, ".env") || fileName == "environment" ||
		(strings.Contains(filePath, "cron") && (strings.Contains(filePath, "daily") || strings.Contains(filePath, "weekly") || strings.Contains(filePath, "monthly")))
}

func (s *TarLayerScanner) getSystemFileType(fileName, filePath string) string {
	if (strings.HasSuffix(fileName, ".service") || strings.HasSuffix(fileName, ".socket") || strings.HasSuffix(fileName, ".timer")) && strings.Contains(filePath, "systemd") {
		return string(artifact.TypeSystemdUnit)
	}
	if strings.HasPrefix(fileName, ".env") || fileName == "environment" {
		return string(artifact.TypeEnvironmentFile)
	}
	if strings.Contains(filePath, "cron") && (strings.Contains(filePath, "daily") || strings.Contains(filePath, "weekly") || strings.Contains(filePath, "monthly")) {
		return string(artifact.TypeCronJob)
	}
	return ""
}

func (s *TarLayerScanner) isConfigFile(fileName string) bool {
	configPatterns := []string{
		".conf", ".config", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".properties",
	}

	for _, pattern := range configPatterns {
		if strings.HasSuffix(fileName, pattern) {
			return true
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
			return true
		}
	}

	return false
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
				ID:     s.generateArtifactID("dpkg:"+name, source),
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
