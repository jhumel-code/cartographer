package scanner

import (
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// BinaryAnalyzer provides deep binary analysis for executables and libraries
type BinaryAnalyzer struct{}

// NewBinaryAnalyzer creates a new binary analyzer
func NewBinaryAnalyzer() *BinaryAnalyzer {
	return &BinaryAnalyzer{}
}

func (b *BinaryAnalyzer) Name() string {
	return "binary-analyzer"
}

func (b *BinaryAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeExecutable,
		artifact.TypeSharedLibrary,
		artifact.TypeStaticLibrary,
		artifact.TypeKernelModule,
		artifact.TypeSystemdService,
		artifact.TypeInitScript,
		artifact.TypeShellScript,
		artifact.TypePythonScript,
		artifact.TypePerlScript,
		artifact.TypeNodeScript,
	}
}

func (b *BinaryAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories and non-executable files
		if info.IsDir() || info.Size() == 0 {
			return nil
		}

		// Check if file is likely a binary
		if b.isBinaryFile(path, info) {
			artifact, err := b.analyzeBinary(path, info, source)
			if err == nil && artifact != nil {
				artifacts = append(artifacts, *artifact)
			}
		}

		return nil
	})

	return artifacts, err
}

// isBinaryFile determines if a file is likely a binary executable or library
func (b *BinaryAnalyzer) isBinaryFile(path string, info fs.FileInfo) bool {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".so" || ext == ".dll" || ext == ".dylib" {
		return true
	}

	// Check if executable
	if info.Mode()&0111 != 0 {
		return true
	}

	// Check common binary directories
	dir := filepath.Dir(path)
	binaryDirs := []string{"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"}
	for _, binDir := range binaryDirs {
		if strings.HasSuffix(dir, binDir) {
			return true
		}
	}

	return false
}

// analyzeBinary performs deep analysis of a binary file
func (b *BinaryAnalyzer) analyzeBinary(path string, info fs.FileInfo, source artifact.Source) (*artifact.Artifact, error) {
	modTime := info.ModTime()

	artifact := &artifact.Artifact{
		Name:        filepath.Base(path),
		Type:        b.determineBinaryType(path, info),
		Path:        path,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    make(map[string]string),
		Source:      source,
	}

	// Analyze binary format and extract metadata
	if err := b.extractBinaryMetadata(path, artifact); err == nil {
		// Binary analysis successful
	}

	// Extract version information using multiple methods
	if version := b.extractBinaryVersion(path, artifact); version != "" {
		artifact.Version = version
		artifact.Metadata["version_method"] = artifact.Metadata["version_detection_method"]
	}

	// Extract dynamic dependencies
	deps, err := b.extractDynamicDependencies(path)
	if err == nil && len(deps) > 0 {
		artifact.Dependencies = deps
		artifact.Metadata["dynamic_dependencies_count"] = fmt.Sprintf("%d", len(deps))
	}

	return artifact, nil
}

// determineBinaryType determines if binary is executable or shared library
func (b *BinaryAnalyzer) determineBinaryType(path string, info fs.FileInfo) artifact.Type {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".so" || ext == ".dll" || ext == ".dylib" || strings.Contains(path, ".so.") {
		return artifact.TypeSharedLibrary
	}
	return artifact.TypeExecutable
}

// extractBinaryMetadata extracts metadata from binary files
func (b *BinaryAnalyzer) extractBinaryMetadata(path string, art *artifact.Artifact) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Try to parse as ELF (Linux)
	if elfFile, err := elf.NewFile(file); err == nil {
		defer elfFile.Close()
		art.Metadata["format"] = "ELF"
		art.Metadata["architecture"] = elfFile.Machine.String()
		art.Metadata["class"] = elfFile.Class.String()
		art.Metadata["endianness"] = elfFile.Data.String()
		art.Metadata["type"] = elfFile.Type.String()

		// Extract version information if available
		if version := b.extractELFVersionFromMetadata(elfFile); version != "" {
			art.Version = version
			art.Metadata["version_detection_method"] = "elf_metadata"
		}

		return nil
	}

	// Reset file pointer
	file.Seek(0, 0)

	// Try to parse as PE (Windows)
	if peFile, err := pe.NewFile(file); err == nil {
		defer peFile.Close()
		art.Metadata["format"] = "PE"
		art.Metadata["machine"] = string(rune(peFile.Machine))

		if peFile.OptionalHeader != nil {
			switch oh := peFile.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				art.Metadata["subsystem"] = string(rune(oh.Subsystem))
			case *pe.OptionalHeader64:
				art.Metadata["subsystem"] = string(rune(oh.Subsystem))
			}
		}

		return nil
	}

	// Reset file pointer
	file.Seek(0, 0)

	// Try to parse as Mach-O (macOS)
	if machoFile, err := macho.NewFile(file); err == nil {
		defer machoFile.Close()
		art.Metadata["format"] = "Mach-O"
		art.Metadata["cpu"] = machoFile.Cpu.String()
		art.Metadata["type"] = machoFile.Type.String()

		return nil
	}

	// If we can't parse it, mark as unknown binary
	art.Metadata["format"] = "unknown"
	return nil
}

// extractELFVersionFromMetadata attempts to extract version information from ELF files quickly
func (b *BinaryAnalyzer) extractELFVersionFromMetadata(elfFile *elf.File) string {
	// Try to find version in dynamic symbols
	if symbols, err := elfFile.DynamicSymbols(); err == nil {
		for _, symbol := range symbols {
			if strings.Contains(strings.ToLower(symbol.Name), "version") {
				// This is a simplified extraction - in practice you'd parse the symbol more carefully
				return "detected"
			}
		}
	}

	// Check for version sections
	for _, section := range elfFile.Sections {
		sectionName := strings.ToLower(section.Name)
		if strings.Contains(sectionName, "version") || strings.Contains(sectionName, ".note") {
			return "detected"
		}
	}

	return ""
}

// extractDynamicDependencies extracts shared library dependencies from binaries
func (b *BinaryAnalyzer) extractDynamicDependencies(path string) ([]string, error) {
	var dependencies []string

	file, err := os.Open(path)
	if err != nil {
		return dependencies, err
	}
	defer file.Close()

	// Try ELF format (Linux)
	if elfFile, err := elf.NewFile(file); err == nil {
		defer elfFile.Close()

		// Get imported libraries
		if libs, err := elfFile.ImportedLibraries(); err == nil {
			dependencies = append(dependencies, libs...)
		}

		return dependencies, nil
	}

	// For non-ELF files, we could use external tools like ldd, otool, etc.
	// For now, return empty list
	return dependencies, nil
}

// extractBinaryVersion attempts to extract version information using multiple methods
func (b *BinaryAnalyzer) extractBinaryVersion(path string, art *artifact.Artifact) string {
	// Method 1: Try --version flag (most common)
	if version := b.tryVersionFlag(path); version != "" {
		art.Metadata["version_detection_method"] = "command_line_flag"
		return version
	}

	// Method 2: Parse from file metadata/resources (Windows PE)
	if version := b.extractPEVersionInfo(path); version != "" {
		art.Metadata["version_detection_method"] = "pe_version_info"
		return version
	}

	// Method 3: Extract from ELF version sections
	if version := b.extractELFVersionInfo(path); version != "" {
		art.Metadata["version_detection_method"] = "elf_version_section"
		return version
	}

	// Method 4: Extract from Mach-O version info
	if version := b.extractMachoVersionInfo(path); version != "" {
		art.Metadata["version_detection_method"] = "macho_version_info"
		return version
	}

	// Method 5: Parse from binary strings (last resort)
	if version := b.extractVersionFromStrings(path); version != "" {
		art.Metadata["version_detection_method"] = "string_analysis"
		return version
	}

	// Method 6: Check filename for version patterns
	if version := b.extractVersionFromFilename(filepath.Base(path)); version != "" {
		art.Metadata["version_detection_method"] = "filename_pattern"
		return version
	}

	art.Metadata["version_detection_method"] = "none"
	return ""
}

// tryVersionFlag attempts to get version by running the binary with common version flags
func (b *BinaryAnalyzer) tryVersionFlag(path string) string {
	versionFlags := []string{"--version", "-v", "-V", "--V", "version", "/version"}

	for _, flag := range versionFlags {
		cmd := exec.Command(path, flag)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		if version := b.parseVersionFromOutput(string(output)); version != "" {
			return version
		}
	}

	// Try just running the binary (some show version info by default)
	cmd := exec.Command(path)
	output, err := cmd.Output()
	if err == nil {
		if version := b.parseVersionFromOutput(string(output)); version != "" {
			return version
		}
	}

	return ""
}

// parseVersionFromOutput extracts version from command output
func (b *BinaryAnalyzer) parseVersionFromOutput(output string) string {
	// Common version patterns
	patterns := []string{
		`(?i)version\s+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?)`,
		`(?i)v(\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?)`,
		`(\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?)`,
		`(?i)release\s+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?)`,
		`(?i)build\s+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// extractPEVersionInfo extracts version from Windows PE files
func (b *BinaryAnalyzer) extractPEVersionInfo(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	peFile, err := pe.NewFile(file)
	if err != nil {
		return ""
	}
	defer peFile.Close()

	// Look for version info in resources
	// This is a simplified approach - a full implementation would parse VS_VERSION_INFO
	for _, section := range peFile.Sections {
		if strings.Contains(section.Name, ".rsrc") {
			// Read resource section and look for version patterns
			data, err := section.Data()
			if err != nil {
				continue
			}

			if version := b.extractVersionFromData(data); version != "" {
				return version
			}
		}
	}

	return ""
}

// extractELFVersionInfo extracts version from ELF files
func (b *BinaryAnalyzer) extractELFVersionInfo(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return ""
	}
	defer elfFile.Close()

	// Check .note sections for version information
	for _, section := range elfFile.Sections {
		if section.Type == elf.SHT_NOTE {
			data, err := section.Data()
			if err != nil {
				continue
			}

			if version := b.extractVersionFromData(data); version != "" {
				return version
			}
		}
	}

	// Check .comment section
	if commentSection := elfFile.Section(".comment"); commentSection != nil {
		data, err := commentSection.Data()
		if err == nil {
			if version := b.extractVersionFromData(data); version != "" {
				return version
			}
		}
	}

	// Check .gnu.version_r and .gnu.version_d sections
	if versionSection := elfFile.Section(".gnu.version_r"); versionSection != nil {
		data, err := versionSection.Data()
		if err == nil {
			if version := b.extractVersionFromData(data); version != "" {
				return version
			}
		}
	}

	return ""
}

// extractMachoVersionInfo extracts version from Mach-O files
func (b *BinaryAnalyzer) extractMachoVersionInfo(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	machoFile, err := macho.NewFile(file)
	if err != nil {
		return ""
	}
	defer machoFile.Close()

	// Check for version in load commands
	for _, load := range machoFile.Loads {
		switch cmd := load.(type) {
		case *macho.Dylib:
			if cmd.Name != "" && strings.Contains(cmd.Name, "version") {
				// Extract version from dylib info
				version := fmt.Sprintf("%d.%d.%d",
					cmd.CurrentVersion>>16,
					(cmd.CurrentVersion>>8)&0xFF,
					cmd.CurrentVersion&0xFF)
				if version != "0.0.0" {
					return version
				}
			}
		}
	}

	// Check sections for version info
	for _, section := range machoFile.Sections {
		if strings.Contains(section.Name, "version") || strings.Contains(section.Name, "__info_plist") {
			data, err := section.Data()
			if err != nil {
				continue
			}

			if version := b.extractVersionFromData(data); version != "" {
				return version
			}
		}
	}

	return ""
}

// extractVersionFromStrings extracts version by analyzing strings in the binary
func (b *BinaryAnalyzer) extractVersionFromStrings(path string) string {
	// Use strings command if available, otherwise read file directly
	cmd := exec.Command("strings", path)
	output, err := cmd.Output()
	if err == nil {
		return b.parseVersionFromOutput(string(output))
	}

	// Fallback: read file and look for printable strings
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Read first 64KB to avoid processing huge binaries
	buffer := make([]byte, 65536)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return ""
	}

	return b.extractVersionFromData(buffer[:n])
}

// extractVersionFromData extracts version patterns from binary data
func (b *BinaryAnalyzer) extractVersionFromData(data []byte) string {
	// Convert to string and look for version patterns
	str := string(data)

	// Common version patterns in binaries
	patterns := []string{
		`(?i)version[:=\s]+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`(?i)v(\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`(\d+\.\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`(?i)release[:=\s]+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`(?i)build[:=\s]+(\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`(?i)\b(\d+\.\d+(?:\.\d+)*)\b`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(str, -1)

		for _, match := range matches {
			if len(match) > 1 {
				version := strings.TrimSpace(match[1])
				// Validate it looks like a real version
				if b.isValidVersion(version) {
					return version
				}
			}
		}
	}

	return ""
}

// extractVersionFromFilename extracts version from filename patterns
func (b *BinaryAnalyzer) extractVersionFromFilename(filename string) string {
	// Remove common extensions
	name := strings.TrimSuffix(filename, filepath.Ext(filename))

	// Common filename version patterns
	patterns := []string{
		`([^-_\s]+)[-_]v?(\d+(?:\.\d+)*(?:-[a-zA-Z0-9._-]+)?)`,
		`([^-_\s]+)-(\d+\.\d+(?:\.\d+)*)`,
		`([^-_\s]+)_(\d+\.\d+(?:\.\d+)*)`,
		`([^-_\s]+)(\d+\.\d+(?:\.\d+)*)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(name); len(matches) > 2 {
			version := strings.TrimSpace(matches[2])
			if b.isValidVersion(version) {
				return version
			}
		}
	}

	return ""
}

// isValidVersion validates if a string looks like a valid version number
func (b *BinaryAnalyzer) isValidVersion(version string) bool {
	if version == "" {
		return false
	}

	// Must start with a digit
	if !strings.HasPrefix(version, "0") && !strings.HasPrefix(version, "1") &&
		!strings.HasPrefix(version, "2") && !strings.HasPrefix(version, "3") &&
		!strings.HasPrefix(version, "4") && !strings.HasPrefix(version, "5") &&
		!strings.HasPrefix(version, "6") && !strings.HasPrefix(version, "7") &&
		!strings.HasPrefix(version, "8") && !strings.HasPrefix(version, "9") {
		return false
	}

	// Should contain at least one dot for major.minor format
	if !strings.Contains(version, ".") {
		// Allow single numbers only if they're reasonable (not dates, addresses, etc.)
		if num, err := strconv.Atoi(version); err == nil {
			return num > 0 && num < 1000 // Reasonable version range
		}
		return false
	}

	// Split and validate each component
	parts := strings.Split(strings.Split(version, "-")[0], ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}

	return true
}
