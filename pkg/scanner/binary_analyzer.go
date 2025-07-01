package scanner

import (
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
		if version := b.extractELFVersion(elfFile); version != "" {
			art.Version = version
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

// extractELFVersion attempts to extract version information from ELF files
func (b *BinaryAnalyzer) extractELFVersion(elfFile *elf.File) string {
	// Try to find version in dynamic section
	if symbols, err := elfFile.DynamicSymbols(); err == nil {
		for _, symbol := range symbols {
			if strings.Contains(symbol.Name, "version") || strings.Contains(symbol.Name, "VERSION") {
				return symbol.Name
			}
		}
	}

	// Try to extract from section names
	for _, section := range elfFile.Sections {
		if strings.Contains(section.Name, "version") {
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
