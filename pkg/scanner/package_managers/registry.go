package package_managers

import (
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

// Scanner name constants
const (
	NPMScannerName      = "npm-scanner"
	YarnScannerName     = "yarn-scanner"
	PnpmScannerName     = "pnpm-scanner"
	PythonScannerName   = "python-scanner"
	MavenScannerName    = "maven-scanner"
	GradleScannerName   = "gradle-scanner"
	GoModScannerName    = "go-mod-scanner"
	CargoScannerName    = "cargo-scanner"
	GemScannerName      = "gem-scanner"
	ComposerScannerName = "composer-scanner"
	NuGetScannerName    = "nuget-scanner"
	SwiftScannerName    = "swift-scanner"
	DartScannerName     = "dart-scanner"
	HaskellScannerName  = "haskell-scanner"
	CRANScannerName     = "cran-scanner"
	HexScannerName      = "hex-scanner"
	ConanScannerName    = "conan-scanner"
	VcpkgScannerName    = "vcpkg-scanner"
)

// Registry provides access to all package manager scanners
type Registry struct {
	*core.ScannerRegistry
}

// NewRegistry creates a new package manager scanner registry
func NewRegistry() *Registry {
	registry := &Registry{
		ScannerRegistry: core.NewScannerRegistry(),
	}

	// Register all package manager scanners
	registry.registerDefaultScanners()

	return registry
}

// registerDefaultScanners registers all available package manager scanners
func (r *Registry) registerDefaultScanners() {
	// JavaScript/Node.js
	r.RegisterScanner(NewNPMScanner())
	r.RegisterScanner(NewYarnScanner())

	// Python
	r.RegisterScanner(NewPythonScanner())

	// Go
	r.RegisterScanner(NewGoScanner())

	// Java
	r.RegisterScanner(NewMavenScanner())

	// Rust
	r.RegisterScanner(NewCargoScanner())

	// Ruby
	r.RegisterScanner(NewGemScanner())

	// PHP
	r.RegisterScanner(NewComposerScanner())

	// Note: Additional scanners to be implemented:
	// - pnpm (JavaScript)
	// - Gradle (Java)
	// - NuGet (.NET)
	// - Swift Package Manager
	// - Dart/Flutter Pub
	// - Conan, Vcpkg (C/C++)
	// - CRAN (R)
	// - Hex (Elixir)
}

// LanguageScannerMapping defines the mapping between languages and their scanners
var LanguageScannerMapping = map[string][]string{
	"javascript": {NPMScannerName, YarnScannerName, PnpmScannerName},
	"node":       {NPMScannerName, YarnScannerName, PnpmScannerName},
	"nodejs":     {NPMScannerName, YarnScannerName, PnpmScannerName},
	"python":     {PythonScannerName},
	"java":       {MavenScannerName, GradleScannerName},
	"go":         {GoModScannerName},
	"golang":     {GoModScannerName},
	"rust":       {CargoScannerName},
	"ruby":       {GemScannerName},
	"php":        {ComposerScannerName},
	"csharp":     {NuGetScannerName},
	"dotnet":     {NuGetScannerName},
	"c#":         {NuGetScannerName},
	"swift":      {SwiftScannerName},
	"dart":       {DartScannerName},
	"flutter":    {DartScannerName},
	"haskell":    {HaskellScannerName},
	"r":          {CRANScannerName},
	"elixir":     {HexScannerName},
	"c":          {ConanScannerName, VcpkgScannerName},
	"cpp":        {ConanScannerName, VcpkgScannerName},
	"c++":        {ConanScannerName, VcpkgScannerName},
}

// GetLanguageSpecificScanners returns scanners for a specific programming language
func (r *Registry) GetLanguageSpecificScanners(language string) []core.Scanner {
	var scanners []core.Scanner

	scannerNames, exists := LanguageScannerMapping[language]
	if !exists {
		return scanners
	}

	for _, scannerName := range scannerNames {
		if scanner, exists := r.GetScanner(scannerName); exists {
			scanners = append(scanners, scanner)
		}
	}

	return scanners
}

// Note: Additional package manager scanners will be implemented in future iterations
// This modular approach allows for easy addition of new package managers without
// modifying the core registry logic.
