package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

const (
	// MaxConfigFileSize defines the maximum size for config files we'll attempt to parse (1MB)
	MaxConfigFileSize = 1024 * 1024

	// ArchitectureHeaderSize defines how many bytes to read for architecture detection
	ArchitectureHeaderSize = 64
)

// BinaryScanner scans for binary files and executables

// BinaryScanner scans for binary files and executables
type BinaryScanner struct {
	*core.BaseScanner
}

// NewBinaryScanner creates a new binary scanner
func NewBinaryScanner() *BinaryScanner {
	patterns := []string{
		"bin/*",
		"sbin/*",
		"usr/bin/*",
		"usr/sbin/*",
		"*.exe",
		"*.dll",
		"*.so",
		"*.dylib",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeExecutable,
		artifact.TypeSharedLibrary,
		artifact.TypeStaticLibrary,
	}

	return &BinaryScanner{
		BaseScanner: core.NewBaseScanner("binary-scanner", supportedTypes, patterns),
	}
}

// Scan analyzes binary files and executables
func (b *BinaryScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	if source.Type != artifact.SourceTypeFilesystem {
		return []artifact.Artifact{}, nil
	}

	return b.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		if !b.matchesBinaryFile(path, source.Location) {
			return nil, nil
		}

		// Check if file is executable
		isExecutable := b.isExecutable(path, info)

		// Determine artifact type based on file extension and executable status
		artifactType := b.determineArtifactType(path, isExecutable)

		metadata := map[string]string{
			"file_size":  strconv.FormatInt(info.Size(), 10),
			"executable": strconv.FormatBool(isExecutable),
			"file_mode":  info.Mode().String(),
		}

		// Add additional metadata for executables
		if isExecutable {
			metadata["architecture"] = b.detectArchitecture(path)
		}

		return []artifact.Artifact{
			b.CreateArtifact(
				filepath.Base(path),
				"", // Version detection could be added later
				artifactType,
				path,
				source,
				metadata,
			),
		}, nil
	})
}

// matchesBinaryFile checks if a file matches binary patterns, including directory-based patterns and binary directory heuristics
func (b *BinaryScanner) matchesBinaryFile(filePath, rootPath string) bool {
	// First check standard patterns using enhanced pattern matching
	if b.MatchesFileWithPath(filePath, rootPath) {
		return true
	}

	// Additional check for files in binary directories (even if they don't match patterns)
	return b.isInBinaryDirectory(filePath, rootPath)
}

// isInBinaryDirectory checks if the file is in a directory that suggests it's a binary
func (b *BinaryScanner) isInBinaryDirectory(filePath, rootPath string) bool {
	relPath, err := filepath.Rel(rootPath, filePath)
	if err != nil {
		return false
	}

	lowerRelPath := strings.ToLower(filepath.ToSlash(relPath))
	binaryDirs := []string{"bin", "sbin", "usr/bin", "usr/sbin"}

	for _, dir := range binaryDirs {
		if strings.HasPrefix(lowerRelPath, dir+"/") || strings.Contains(lowerRelPath, "/"+dir+"/") {
			return true
		}
	}
	return false
}

// isExecutable checks if a file is executable
func (b *BinaryScanner) isExecutable(path string, info os.FileInfo) bool {
	// Check file permissions for execute bit
	mode := info.Mode()
	if mode&0111 != 0 {
		return true
	}

	// On Windows, check for executable extensions
	ext := strings.ToLower(filepath.Ext(path))
	windowsExecs := []string{".exe", ".bat", ".cmd", ".com", ".scr", ".msi", ".ps1"}
	for _, execExt := range windowsExecs {
		if ext == execExt {
			return true
		}
	}

	return false
}

// determineArtifactType determines the artifact type based on file characteristics
func (b *BinaryScanner) determineArtifactType(path string, isExecutable bool) artifact.Type {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".so", ".dylib":
		return artifact.TypeSharedLibrary
	case ".a", ".lib":
		return artifact.TypeStaticLibrary
	case ".dll":
		return artifact.TypeSharedLibrary
	default:
		if isExecutable {
			return artifact.TypeExecutable
		}
		// Default to executable for files in typical binary directories
		dir := filepath.Dir(path)
		if strings.Contains(dir, "bin") || strings.Contains(dir, "sbin") {
			return artifact.TypeExecutable
		}
		return artifact.TypeExecutable
	}
}

// detectArchitecture attempts to detect the architecture of a binary file
func (b *BinaryScanner) detectArchitecture(path string) string {
	// Try to read the first few bytes to identify the format
	file, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	header := make([]byte, ArchitectureHeaderSize)
	n, err := file.Read(header)
	if err != nil || n < 4 {
		return "unknown"
	}

	// ELF magic number
	if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		if len(header) > 4 {
			switch header[4] {
			case 1:
				return "x86"
			case 2:
				return "x86_64"
			}
		}
		return "elf"
	}

	// PE magic number (Windows)
	if header[0] == 'M' && header[1] == 'Z' {
		return "pe"
	}

	// Mach-O magic numbers (macOS)
	if len(header) >= 4 {
		magic := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24
		switch magic {
		case 0xfeedface, 0xfeedfacf:
			return "mach-o"
		}
	}

	return "unknown"
}

// ServiceScanner scans for system services
type ServiceScanner struct {
	*core.BaseScanner
}

// NewServiceScanner creates a new service scanner
func NewServiceScanner() *ServiceScanner {
	patterns := []string{
		"*.service",
		"*.socket",
		"*.timer",
		"*.target",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeSystemdUnit,
	}

	return &ServiceScanner{
		BaseScanner: core.NewBaseScanner("service-scanner", supportedTypes, patterns),
	}
}

// Scan analyzes systemd service files and extracts metadata
func (s *ServiceScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	if source.Type != artifact.SourceTypeFilesystem {
		return []artifact.Artifact{}, nil
	}

	return s.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		if !s.MatchesFile(filepath.Base(path), path) {
			return nil, nil
		}

		metadata, err := s.parseServiceFile(path)
		if err != nil {
			// Log error but continue scanning
			metadata = map[string]string{
				"parse_error": err.Error(),
			}
		}

		// Add file metadata
		metadata["file_size"] = strconv.FormatInt(info.Size(), 10)
		metadata["file_mode"] = info.Mode().String()

		return []artifact.Artifact{
			s.CreateArtifact(
				filepath.Base(path),
				"", // Services typically don't have versions
				artifact.TypeSystemdUnit,
				path,
				source,
				metadata,
			),
		}, nil
	})
}

// parseServiceFile parses a systemd unit file and extracts key information
func (s *ServiceScanner) parseServiceFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open service file: %w", err)
	}
	defer file.Close()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if s.shouldSkipLine(line) {
			continue
		}

		if s.isSection(line) {
			currentSection = s.extractSectionName(line)
			continue
		}

		if s.isKeyValuePair(line) {
			s.processKeyValuePair(line, currentSection, metadata)
		}
	}

	if err := scanner.Err(); err != nil {
		return metadata, fmt.Errorf("error reading service file: %w", err)
	}

	return metadata, nil
}

// shouldSkipLine checks if a line should be skipped during parsing
func (s *ServiceScanner) shouldSkipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// isSection checks if a line is a section header
func (s *ServiceScanner) isSection(line string) bool {
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
}

// extractSectionName extracts the section name from a section header line
func (s *ServiceScanner) extractSectionName(line string) string {
	return strings.Trim(line, "[]")
}

// isKeyValuePair checks if a line contains a key-value pair
func (s *ServiceScanner) isKeyValuePair(line string) bool {
	return strings.Contains(line, "=")
}

// processKeyValuePair processes a key-value pair line and updates metadata
func (s *ServiceScanner) processKeyValuePair(line, currentSection string, metadata map[string]string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// Store with section prefix if we're in a section
	if currentSection != "" {
		metadata[fmt.Sprintf("%s.%s", currentSection, key)] = value
	} else {
		metadata[key] = value
	}

	// Extract commonly used fields for easier access
	s.extractCommonFields(key, value, metadata)
}

// extractCommonFields extracts commonly used fields for easier access
func (s *ServiceScanner) extractCommonFields(key, value string, metadata map[string]string) {
	commonFields := map[string]string{
		"Description": "description",
		"ExecStart":   "exec_start",
		"User":        "user",
		"Type":        "service_type",
		"WantedBy":    "wanted_by",
	}

	if mappedKey, exists := commonFields[key]; exists {
		metadata[mappedKey] = value
	}
}

// ConfigScanner scans for configuration files
type ConfigScanner struct {
	*core.BaseScanner
}

// NewConfigScanner creates a new config scanner
func NewConfigScanner() *ConfigScanner {
	patterns := []string{
		"*.conf",
		"*.config",
		"*.cfg",
		"*.ini",
		"*.properties",
		"*.yaml",
		"*.yml",
		"*.toml",
		"*.json",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeConfigFile,
	}

	return &ConfigScanner{
		BaseScanner: core.NewBaseScanner("config-scanner", supportedTypes, patterns),
	}
}

// Scan analyzes configuration files and extracts metadata
func (c *ConfigScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	if source.Type != artifact.SourceTypeFilesystem {
		return []artifact.Artifact{}, nil
	}

	return c.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		if !c.MatchesFile(filepath.Base(path), path) {
			return nil, nil
		}

		metadata := c.extractConfigMetadata(path, info)

		return []artifact.Artifact{
			c.CreateArtifact(
				filepath.Base(path),
				"", // Config files typically don't have versions
				artifact.TypeConfigFile,
				path,
				source,
				metadata,
			),
		}, nil
	})
}

// extractConfigMetadata extracts metadata from configuration files
func (c *ConfigScanner) extractConfigMetadata(path string, info os.FileInfo) map[string]string {
	configType := c.detectConfigType(path)

	metadata := map[string]string{
		"file_size": strconv.FormatInt(info.Size(), 10),
		"file_mode": info.Mode().String(),
		"format":    configType,
	}

	// Try to extract additional metadata based on file type
	if additionalMeta := c.parseConfigFile(path, configType); additionalMeta != nil {
		for k, v := range additionalMeta {
			metadata[k] = v
		}
	}

	return metadata
}

// detectConfigType determines the configuration file format
func (c *ConfigScanner) detectConfigType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	switch ext {
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".ini":
		return "ini"
	case ".conf":
		return "conf"
	case ".config":
		return "config"
	case ".cfg":
		return "cfg"
	case ".properties":
		return "properties"
	default:
		// Check for common config file names without extensions
		if strings.Contains(base, "config") {
			return "config"
		}
		return "unknown"
	}
}

// parseConfigFile attempts to parse config files and extract basic metadata
func (c *ConfigScanner) parseConfigFile(path, configType string) map[string]string {
	metadata := make(map[string]string)

	// Only attempt to parse smaller files to avoid performance issues
	info, err := os.Stat(path)
	if err != nil || info.Size() > MaxConfigFileSize { // Skip files larger than 1MB
		if err != nil {
			metadata["parse_error"] = err.Error()
		}
		return metadata
	}

	file, err := os.Open(path)
	if err != nil {
		metadata["parse_error"] = err.Error()
		return metadata
	}
	defer file.Close()

	return c.parseByType(file, configType, metadata)
}

// parseByType parses the config file based on its detected type
func (c *ConfigScanner) parseByType(file *os.File, configType string, metadata map[string]string) map[string]string {
	switch configType {
	case "ini", "conf", "config", "cfg":
		return c.parseINIStyle(file, metadata)
	case "properties":
		return c.parseProperties(file, metadata)
	default:
		// For other formats (JSON, YAML, TOML), we'd need specific parsers
		// For now, just count lines and estimate complexity
		return c.parseGeneric(file, metadata)
	}
}

// parseINIStyle parses INI-style configuration files
func (c *ConfigScanner) parseINIStyle(file *os.File, metadata map[string]string) map[string]string {
	scanner := bufio.NewScanner(file)
	sectionCount := 0
	keyCount := 0
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sectionCount++
			currentSection = strings.Trim(line, "[]")
			if sectionCount == 1 {
				metadata["first_section"] = currentSection
			}
		} else if strings.Contains(line, "=") {
			keyCount++
		}
	}

	metadata["section_count"] = strconv.Itoa(sectionCount)
	metadata["key_count"] = strconv.Itoa(keyCount)
	return metadata
}

// parseProperties parses Java-style properties files
func (c *ConfigScanner) parseProperties(file *os.File, metadata map[string]string) map[string]string {
	scanner := bufio.NewScanner(file)
	keyCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		if strings.Contains(line, "=") || strings.Contains(line, ":") {
			keyCount++
		}
	}

	metadata["key_count"] = strconv.Itoa(keyCount)
	return metadata
}

// parseGeneric provides basic parsing for unknown config file formats
func (c *ConfigScanner) parseGeneric(file *os.File, metadata map[string]string) map[string]string {
	scanner := bufio.NewScanner(file)
	lineCount := 0
	nonEmptyLines := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			nonEmptyLines++
		}
	}

	metadata["line_count"] = strconv.Itoa(lineCount)
	metadata["non_empty_lines"] = strconv.Itoa(nonEmptyLines)
	return metadata
}
