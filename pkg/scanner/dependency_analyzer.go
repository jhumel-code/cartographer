package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// DependencyAnalyzer analyzes package dependencies and relationships
type DependencyAnalyzer struct{}

// NewDependencyAnalyzer creates a new dependency analyzer
func NewDependencyAnalyzer() *DependencyAnalyzer {
	return &DependencyAnalyzer{}
}

func (d *DependencyAnalyzer) Name() string {
	return "dependency-analyzer"
}

func (d *DependencyAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		// Linux Distribution Package Managers
		artifact.TypeDebianPackage,
		artifact.TypeRPMPackage,
		artifact.TypeAlpinePackage,
		artifact.TypeArchPackage,
		artifact.TypeGentooPackage,
		artifact.TypeSnapPackage,
		artifact.TypeFlatpakPackage,
		artifact.TypeAppImagePackage,

		// Language Package Managers
		artifact.TypeNpmPackage,
		artifact.TypePythonPackage,
		artifact.TypeGoModule,
		artifact.TypeRustCrate,
		artifact.TypeRubyGem,
		artifact.TypePHPPackage,
		artifact.TypeMavenPackage,
		artifact.TypeGradlePackage,
		artifact.TypeDotNetPackage,
		artifact.TypeSwiftPackage,
		artifact.TypeDartPackage,
		artifact.TypeCocoaPod,
		artifact.TypeConanPackage,
		artifact.TypeCRANPackage,
		artifact.TypeHexPackage,
		artifact.TypeHaskellPackage,
		artifact.TypeTerraformConfig,
	}
}

func (d *DependencyAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		fileName := strings.ToLower(info.Name())

		// Analyze different package manager files
		switch {
		// Cargo (Rust)
		case fileName == "cargo.toml":
			cargoArtifacts := d.analyzeCargoToml(path, info, source)
			artifacts = append(artifacts, cargoArtifacts...)
		case fileName == "cargo.lock":
			cargoLockArtifacts := d.analyzeCargoLock(path, info, source)
			artifacts = append(artifacts, cargoLockArtifacts...)

		// CocoaPods (iOS/macOS)
		case fileName == "podfile":
			podArtifacts := d.analyzePodfile(path, info, source)
			artifacts = append(artifacts, podArtifacts...)
		case fileName == "podfile.lock":
			podLockArtifacts := d.analyzePodfileLock(path, info, source)
			artifacts = append(artifacts, podLockArtifacts...)

		// Composer (PHP)
		case fileName == "composer.json":
			composerArtifacts := d.analyzeComposerJson(path, info, source)
			artifacts = append(artifacts, composerArtifacts...)
		case fileName == "composer.lock":
			composerLockArtifacts := d.analyzeComposerLock(path, info, source)
			artifacts = append(artifacts, composerLockArtifacts...)

		// Conan (C/C++)
		case fileName == "conanfile.txt" || fileName == "conanfile.py":
			conanArtifacts := d.analyzeConanfile(path, info, source)
			artifacts = append(artifacts, conanArtifacts...)
		case fileName == "conan.lock":
			conanLockArtifacts := d.analyzeConanLock(path, info, source)
			artifacts = append(artifacts, conanLockArtifacts...)

		// CRAN (R)
		case fileName == "description":
			cranArtifacts := d.analyzeCRANDescription(path, info, source)
			artifacts = append(artifacts, cranArtifacts...)
		case fileName == "renv.lock":
			renvArtifacts := d.analyzeRenvLock(path, info, source)
			artifacts = append(artifacts, renvArtifacts...)

		// Go modules
		case fileName == "go.mod":
			goModArtifacts := d.analyzeGoMod(path, info, source)
			artifacts = append(artifacts, goModArtifacts...)
		case fileName == "go.sum":
			goSumArtifacts := d.analyzeGoSum(path, info, source)
			artifacts = append(artifacts, goSumArtifacts...)

		// Gradle (Java/Kotlin/Scala)
		case fileName == "build.gradle" || fileName == "build.gradle.kts":
			gradleArtifacts := d.analyzeGradleBuild(path, info, source)
			artifacts = append(artifacts, gradleArtifacts...)
		case fileName == "gradle.lockfile":
			gradleLockArtifacts := d.analyzeGradleLock(path, info, source)
			artifacts = append(artifacts, gradleLockArtifacts...)

		// Hackage (Haskell)
		case fileName == "stack.yaml":
			stackArtifacts := d.analyzeStackYaml(path, info, source)
			artifacts = append(artifacts, stackArtifacts...)
		case fileName == "cabal.project":
			cabalArtifacts := d.analyzeCabalProject(path, info, source)
			artifacts = append(artifacts, cabalArtifacts...)

		// Hex (Elixir/Erlang)
		case fileName == "mix.exs":
			mixArtifacts := d.analyzeMixExs(path, info, source)
			artifacts = append(artifacts, mixArtifacts...)
		case fileName == "mix.lock":
			mixLockArtifacts := d.analyzeMixLock(path, info, source)
			artifacts = append(artifacts, mixLockArtifacts...)

		// Maven (Java)
		case fileName == "pom.xml":
			mavenArtifacts := d.analyzeMavenPom(path, info, source)
			artifacts = append(artifacts, mavenArtifacts...)

		// NPM (Node.js)
		case fileName == "package.json":
			npmArtifacts := d.analyzePackageJson(path, info, source)
			artifacts = append(artifacts, npmArtifacts...)
		case fileName == "package-lock.json":
			npmLockArtifacts := d.analyzeNpmLock(path, info, source)
			artifacts = append(artifacts, npmLockArtifacts...)
		case fileName == "yarn.lock":
			yarnLockArtifacts := d.analyzeYarnLock(path, info, source)
			artifacts = append(artifacts, yarnLockArtifacts...)

		// NuGet (.NET)
		case fileName == "packages.config":
			nugetArtifacts := d.analyzeNuGetPackagesConfig(path, info, source)
			artifacts = append(artifacts, nugetArtifacts...)
		case fileName == "packages.lock.json":
			nugetLockArtifacts := d.analyzeNuGetLock(path, info, source)
			artifacts = append(artifacts, nugetLockArtifacts...)

		// Pub (Dart/Flutter)
		case fileName == "pubspec.yaml":
			pubArtifacts := d.analyzePubspec(path, info, source)
			artifacts = append(artifacts, pubArtifacts...)
		case fileName == "pubspec.lock":
			pubLockArtifacts := d.analyzePubspecLock(path, info, source)
			artifacts = append(artifacts, pubLockArtifacts...)

		// PyPI (Python)
		case fileName == "requirements.txt":
			pypiArtifacts := d.analyzeRequirementsTxt(path, info, source)
			artifacts = append(artifacts, pypiArtifacts...)
		case fileName == "pipfile":
			pipfileArtifacts := d.analyzePipfile(path, info, source)
			artifacts = append(artifacts, pipfileArtifacts...)
		case fileName == "pyproject.toml":
			pyprojectArtifacts := d.analyzePyprojectToml(path, info, source)
			artifacts = append(artifacts, pyprojectArtifacts...)

		// RubyGems
		case fileName == "gemfile":
			gemArtifacts := d.analyzeGemfile(path, info, source)
			artifacts = append(artifacts, gemArtifacts...)
		case fileName == "gemfile.lock":
			gemLockArtifacts := d.analyzeGemfileLock(path, info, source)
			artifacts = append(artifacts, gemLockArtifacts...)

		// Swift Package Manager
		case fileName == "package.swift":
			swiftArtifacts := d.analyzeSwiftPackage(path, info, source)
			artifacts = append(artifacts, swiftArtifacts...)
		case fileName == "package.resolved":
			swiftLockArtifacts := d.analyzeSwiftPackageResolved(path, info, source)
			artifacts = append(artifacts, swiftLockArtifacts...)

		// Terraform
		case strings.HasSuffix(fileName, ".tf"):
			terraformArtifacts := d.analyzeTerraformFile(path, info, source)
			artifacts = append(artifacts, terraformArtifacts...)
		case fileName == "terraform.lock.hcl":
			terraformLockArtifacts := d.analyzeTerraformLock(path, info, source)
			artifacts = append(artifacts, terraformLockArtifacts...)

		// Linux Distribution Package Managers
		// Debian/Ubuntu (dpkg/apt)
		case fileName == "dpkg.list" || fileName == "status" && (strings.Contains(path, "/var/lib/dpkg/") || strings.Contains(path, "\\var\\lib\\dpkg\\")):
			debianArtifacts := d.analyzeDebianPackages(path, info, source)
			artifacts = append(artifacts, debianArtifacts...)
		case fileName == "sources.list" || strings.HasSuffix(fileName, ".list") && (strings.Contains(path, "/etc/apt/") || strings.Contains(path, "\\etc\\apt\\")):
			debianSourcesArtifacts := d.analyzeDebianSources(path, info, source)
			artifacts = append(artifacts, debianSourcesArtifacts...)

		// RPM-based (RHEL, CentOS, Fedora, SUSE)
		case fileName == "rpm.list" || strings.HasSuffix(fileName, ".rpm"):
			rpmArtifacts := d.analyzeRPMPackages(path, info, source)
			artifacts = append(artifacts, rpmArtifacts...)

		// Alpine (apk)
		case fileName == "installed" && (strings.Contains(path, "/lib/apk/db/") || strings.Contains(path, "\\lib\\apk\\db\\")):
			alpineArtifacts := d.analyzeAlpinePackages(path, info, source)
			artifacts = append(artifacts, alpineArtifacts...)
		case fileName == "repositories" && (strings.Contains(path, "/etc/apk/") || strings.Contains(path, "\\etc\\apk\\")):
			alpineReposArtifacts := d.analyzeAlpineRepositories(path, info, source)
			artifacts = append(artifacts, alpineReposArtifacts...)

		// Arch Linux (pacman)
		case fileName == "local" && (strings.Contains(path, "/var/lib/pacman/") || strings.Contains(path, "\\var\\lib\\pacman\\")):
			archArtifacts := d.analyzeArchPackages(path, info, source)
			artifacts = append(artifacts, archArtifacts...)
		case fileName == "pacman.conf":
			archConfigArtifacts := d.analyzeArchConfig(path, info, source)
			artifacts = append(artifacts, archConfigArtifacts...)

		// Gentoo (portage)
		case fileName == "world" && (strings.Contains(path, "/var/lib/portage/") || strings.Contains(path, "\\var\\lib\\portage\\")):
			gentooArtifacts := d.analyzeGentooPackages(path, info, source)
			artifacts = append(artifacts, gentooArtifacts...)

		// Snap packages
		case strings.HasSuffix(fileName, ".snap") || fileName == "snap.yaml":
			snapArtifacts := d.analyzeSnapPackages(path, info, source)
			artifacts = append(artifacts, snapArtifacts...)

		// Flatpak packages
		case strings.HasSuffix(fileName, ".flatpak") || fileName == "metadata" && (strings.Contains(path, "/var/lib/flatpak/") || strings.Contains(path, "\\var\\lib\\flatpak\\")):
			flatpakArtifacts := d.analyzeFlatpakPackages(path, info, source)
			artifacts = append(artifacts, flatpakArtifacts...)

		// AppImage packages
		case strings.HasSuffix(fileName, ".appimage"):
			appimageArtifacts := d.analyzeAppImagePackages(path, info, source)
			artifacts = append(artifacts, appimageArtifacts...)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return artifacts, nil
}

// Cargo (Rust) implementations
func (d *DependencyAnalyzer) analyzeCargoToml(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	// Implementation for Cargo.toml parsing
	return d.parseCargoToml(path, source)
}

func (d *DependencyAnalyzer) analyzeCargoLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	// Implementation for Cargo.lock parsing
	return d.parseCargoLock(path, source)
}

// CocoaPods implementations
func (d *DependencyAnalyzer) analyzePodfile(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePodfile(path, source)
}

func (d *DependencyAnalyzer) analyzePodfileLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePodfileLock(path, source)
}

// Composer (PHP) implementations
func (d *DependencyAnalyzer) analyzeComposerJson(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseComposerJson(path, source)
}

func (d *DependencyAnalyzer) analyzeComposerLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseComposerLock(path, source)
}

// Conan (C/C++) implementations
func (d *DependencyAnalyzer) analyzeConanfile(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseConanfile(path, source)
}

func (d *DependencyAnalyzer) analyzeConanLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseConanLock(path, source)
}

// CRAN (R) implementations
func (d *DependencyAnalyzer) analyzeCRANDescription(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseCRANDescription(path, source)
}

func (d *DependencyAnalyzer) analyzeRenvLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseRenvLock(path, source)
}

// Go implementations
func (d *DependencyAnalyzer) analyzeGoMod(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGoMod(path, source)
}

func (d *DependencyAnalyzer) analyzeGoSum(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGoSum(path, source)
}

// Gradle implementations
func (d *DependencyAnalyzer) analyzeGradleBuild(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGradleBuild(path, source)
}

func (d *DependencyAnalyzer) analyzeGradleLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGradleLock(path, source)
}

// Hackage (Haskell) implementations
func (d *DependencyAnalyzer) analyzeStackYaml(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseStackYaml(path, source)
}

func (d *DependencyAnalyzer) analyzeCabalProject(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseCabalProject(path, source)
}

// Hex (Elixir/Erlang) implementations
func (d *DependencyAnalyzer) analyzeMixExs(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseMixExs(path, source)
}

func (d *DependencyAnalyzer) analyzeMixLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseMixLock(path, source)
}

// Maven implementations
func (d *DependencyAnalyzer) analyzeMavenPom(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseMavenPom(path, source)
}

// NPM implementations
func (d *DependencyAnalyzer) analyzePackageJson(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePackageJson(path, source)
}

func (d *DependencyAnalyzer) analyzeNpmLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseNpmLock(path, source)
}

func (d *DependencyAnalyzer) analyzeYarnLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseYarnLock(path, source)
}

// NuGet implementations
func (d *DependencyAnalyzer) analyzeNuGetPackagesConfig(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseNuGetPackagesConfig(path, source)
}

func (d *DependencyAnalyzer) analyzeNuGetLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseNuGetLock(path, source)
}

// Pub (Dart/Flutter) implementations
func (d *DependencyAnalyzer) analyzePubspec(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePubspec(path, source)
}

func (d *DependencyAnalyzer) analyzePubspecLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePubspecLock(path, source)
}

// PyPI implementations
func (d *DependencyAnalyzer) analyzeRequirementsTxt(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseRequirementsTxt(path, source)
}

func (d *DependencyAnalyzer) analyzePipfile(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePipfile(path, source)
}

func (d *DependencyAnalyzer) analyzePyprojectToml(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parsePyprojectToml(path, source)
}

// RubyGems implementations
func (d *DependencyAnalyzer) analyzeGemfile(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGemfile(path, source)
}

func (d *DependencyAnalyzer) analyzeGemfileLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGemfileLock(path, source)
}

// Swift implementations
func (d *DependencyAnalyzer) analyzeSwiftPackage(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseSwiftPackage(path, source)
}

func (d *DependencyAnalyzer) analyzeSwiftPackageResolved(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseSwiftPackageResolved(path, source)
}

// Terraform implementations
func (d *DependencyAnalyzer) analyzeTerraformFile(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseTerraformFile(path, source)
}

func (d *DependencyAnalyzer) analyzeTerraformLock(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseTerraformLock(path, source)
}

// Parser implementations for each package manager

// Cargo (Rust) parsers
func (d *DependencyAnalyzer) parseCargoToml(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inDependencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[dependencies]" || line == "[dev-dependencies]" || line == "[build-dependencies]" {
			inDependencies = true
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[dependencies]" && line != "[dev-dependencies]" && line != "[build-dependencies]" {
			inDependencies = false
			continue
		}

		if inDependencies && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeRustCrate,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "cargo",
						"source_file":     "Cargo.toml",
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseCargoLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// Cargo.lock contains resolved dependency information
	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentPackage string
	var currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "name = ") {
			currentPackage = strings.Trim(strings.TrimPrefix(line, "name = "), "\"'")
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"'")

			if currentPackage != "" && currentVersion != "" {
				artifacts = append(artifacts, artifact.Artifact{
					Name:    currentPackage,
					Version: currentVersion,
					Type:    artifact.TypeRustCrate,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "cargo",
						"source_file":     "Cargo.lock",
						"resolved":        "true",
					},
				})
				currentPackage = ""
				currentVersion = ""
			}
		}
	}

	return artifacts
}

// CocoaPods parsers
func (d *DependencyAnalyzer) parsePodfile(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	podRegex := regexp.MustCompile(`pod\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := podRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
			}

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypeCocoaPod,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "cocoapods",
					"source_file":     "Podfile",
				},
			})
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parsePodfileLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	podRegex := regexp.MustCompile(`-\s+([^(]+)\s*\(([^)]+)\)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := podRegex.FindStringSubmatch(line); matches != nil {
			name := strings.TrimSpace(matches[1])
			version := strings.TrimSpace(matches[2])

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypeCocoaPod,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "cocoapods",
					"source_file":     "Podfile.lock",
					"resolved":        "true",
				},
			})
		}
	}

	return artifacts
}

// Composer (PHP) parsers
func (d *DependencyAnalyzer) parseComposerJson(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var composerData struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.NewDecoder(file).Decode(&composerData); err != nil {
		return artifacts
	}

	// Process regular dependencies
	for name, version := range composerData.Require {
		if name == "php" {
			continue // Skip PHP version requirement
		}

		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: version,
			Type:    artifact.TypePHPPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "composer",
				"source_file":     "composer.json",
				"dependency_type": "production",
			},
		})
	}

	// Process dev dependencies
	for name, version := range composerData.RequireDev {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: version,
			Type:    artifact.TypePHPPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "composer",
				"source_file":     "composer.json",
				"dependency_type": "development",
			},
		})
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseComposerLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var lockData struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts
	}

	// Process production packages
	for _, pkg := range lockData.Packages {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    pkg.Name,
			Version: pkg.Version,
			Type:    artifact.TypePHPPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "composer",
				"source_file":     "composer.lock",
				"dependency_type": "production",
				"resolved":        "true",
			},
		})
	}

	// Process dev packages
	for _, pkg := range lockData.PackagesDev {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    pkg.Name,
			Version: pkg.Version,
			Type:    artifact.TypePHPPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "composer",
				"source_file":     "composer.lock",
				"dependency_type": "development",
				"resolved":        "true",
			},
		})
	}

	return artifacts
}

// Conan (C/C++) parsers
func (d *DependencyAnalyzer) parseConanfile(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	if strings.HasSuffix(path, ".txt") {
		// Parse conanfile.txt
		inRequires := false

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if line == "[requires]" {
				inRequires = true
				continue
			}

			if strings.HasPrefix(line, "[") && line != "[requires]" {
				inRequires = false
				continue
			}

			if inRequires && line != "" && !strings.HasPrefix(line, "#") {
				parts := strings.Split(line, "/")
				if len(parts) >= 2 {
					name := parts[0]
					version := parts[1]
					if atIndex := strings.Index(version, "@"); atIndex != -1 {
						version = version[:atIndex]
					}

					artifacts = append(artifacts, artifact.Artifact{
						Name:    name,
						Version: version,
						Type:    artifact.TypeConanPackage,
						Path:    path,
						Source:  source,
						Metadata: map[string]string{
							"package_manager": "conan",
							"source_file":     "conanfile.txt",
						},
					})
				}
			}
		}
	} else {
		// Parse conanfile.py (basic regex-based parsing)
		requiresRegex := regexp.MustCompile(`requires\s*=\s*["']([^"']+)["']`)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if matches := requiresRegex.FindStringSubmatch(line); matches != nil {
				requirement := matches[1]
				parts := strings.Split(requirement, "/")
				if len(parts) >= 2 {
					name := parts[0]
					version := parts[1]
					if atIndex := strings.Index(version, "@"); atIndex != -1 {
						version = version[:atIndex]
					}

					artifacts = append(artifacts, artifact.Artifact{
						Name:    name,
						Version: version,
						Type:    artifact.TypeConanPackage,
						Path:    path,
						Source:  source,
						Metadata: map[string]string{
							"package_manager": "conan",
							"source_file":     "conanfile.py",
						},
					})
				}
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseConanLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var lockData struct {
		GraphLock struct {
			Nodes map[string]struct {
				Ref string `json:"ref"`
			} `json:"nodes"`
		} `json:"graph_lock"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts
	}

	for _, node := range lockData.GraphLock.Nodes {
		if node.Ref != "" {
			parts := strings.Split(node.Ref, "/")
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]
				if atIndex := strings.Index(version, "@"); atIndex != -1 {
					version = version[:atIndex]
				}

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeConanPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "conan",
						"source_file":     "conan.lock",
						"resolved":        "true",
					},
				})
			}
		}
	}

	return artifacts
}

// CRAN (R) parsers
func (d *DependencyAnalyzer) parseCRANDescription(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Depends:") || strings.HasPrefix(line, "Imports:") || strings.HasPrefix(line, "Suggests:") {
			dependencyType := "production"
			if strings.HasPrefix(line, "Suggests:") {
				dependencyType = "suggested"
			}

			deps := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			packages := strings.Split(deps, ",")

			for _, pkg := range packages {
				pkg = strings.TrimSpace(pkg)
				if pkg == "" || pkg == "R" {
					continue
				}

				// Extract package name and version constraint
				name := pkg
				version := ""
				if parenIndex := strings.Index(pkg, "("); parenIndex != -1 {
					name = strings.TrimSpace(pkg[:parenIndex])
					version = strings.TrimSpace(pkg[parenIndex:])
				}

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeCRANPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "cran",
						"source_file":     "DESCRIPTION",
						"dependency_type": dependencyType,
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseRenvLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var lockData struct {
		Packages map[string]struct {
			Package string `json:"Package"`
			Version string `json:"Version"`
			Source  string `json:"Source"`
		} `json:"Packages"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts
	}

	for _, pkg := range lockData.Packages {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    pkg.Package,
			Version: pkg.Version,
			Type:    artifact.TypeCRANPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "renv",
				"source_file":     "renv.lock",
				"resolved":        "true",
			},
		})
	}

	return artifacts
}

// Go parsers
func (d *DependencyAnalyzer) parseGoMod(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}

		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if strings.HasPrefix(line, "require ") && !inRequire {
			// Single line require
			line = strings.TrimPrefix(line, "require ")
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeGoModule,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "go",
						"source_file":     "go.mod",
					},
				})
			}
		} else if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeGoModule,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "go",
						"source_file":     "go.mod",
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseGoSum(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			name := parts[0]
			version := parts[1]

			// Remove /go.mod suffix from version if present
			if strings.HasSuffix(version, "/go.mod") {
				version = strings.TrimSuffix(version, "/go.mod")
			}

			key := name + "@" + version
			if !seen[key] {
				seen[key] = true

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeGoModule,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "go",
						"source_file":     "go.sum",
						"resolved":        "true",
					},
				})
			}
		}
	}

	return artifacts
}

// Gradle parsers
func (d *DependencyAnalyzer) parseGradleBuild(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	depRegex := regexp.MustCompile(`(?:implementation|api|compile|testImplementation|testCompile|runtimeOnly|compileOnly)\s+['"]([^'"]+)['"]`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := depRegex.FindStringSubmatch(line); matches != nil {
			dependency := matches[1]
			parts := strings.Split(dependency, ":")

			if len(parts) >= 2 {
				group := parts[0]
				name := parts[1]
				version := ""
				if len(parts) >= 3 {
					version = parts[2]
				}

				fullName := group + ":" + name

				artifacts = append(artifacts, artifact.Artifact{
					Name:    fullName,
					Version: version,
					Type:    artifact.TypeGradlePackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "gradle",
						"source_file":     filepath.Base(path),
						"group":           group,
						"artifact":        name,
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseGradleLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, ":") && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				group := parts[0]
				name := parts[1]
				version := parts[2]

				fullName := group + ":" + name

				artifacts = append(artifacts, artifact.Artifact{
					Name:    fullName,
					Version: version,
					Type:    artifact.TypeGradlePackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "gradle",
						"source_file":     "gradle.lockfile",
						"resolved":        "true",
						"group":           group,
						"artifact":        name,
					},
				})
			}
		}
	}

	return artifacts
}

// Maven parser
func (d *DependencyAnalyzer) parseMavenPom(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	type Dependency struct {
		GroupId    string `xml:"groupId"`
		ArtifactId string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}

	type Project struct {
		Dependencies struct {
			Dependency []Dependency `xml:"dependency"`
		} `xml:"dependencies"`
	}

	var project Project
	if err := xml.NewDecoder(file).Decode(&project); err != nil {
		return artifacts
	}

	for _, dep := range project.Dependencies.Dependency {
		if dep.GroupId != "" && dep.ArtifactId != "" {
			name := dep.GroupId + ":" + dep.ArtifactId

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: dep.Version,
				Type:    artifact.TypeMavenPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "maven",
					"source_file":     "pom.xml",
					"group_id":        dep.GroupId,
					"artifact_id":     dep.ArtifactId,
					"scope":           dep.Scope,
				},
			})
		}
	}

	return artifacts
}

// NPM parsers
func (d *DependencyAnalyzer) parsePackageJson(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var packageData struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.NewDecoder(file).Decode(&packageData); err != nil {
		return artifacts
	}

	// Process production dependencies
	for name, version := range packageData.Dependencies {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: version,
			Type:    artifact.TypeNpmPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "npm",
				"source_file":     "package.json",
				"dependency_type": "production",
			},
		})
	}

	// Process dev dependencies
	for name, version := range packageData.DevDependencies {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: version,
			Type:    artifact.TypeNpmPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "npm",
				"source_file":     "package.json",
				"dependency_type": "development",
			},
		})
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseNpmLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var lockData struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts
	}

	for name, dep := range lockData.Dependencies {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: dep.Version,
			Type:    artifact.TypeNpmPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "npm",
				"source_file":     "package-lock.json",
				"resolved":        "true",
			},
		})
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseYarnLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^"?([^@"]+)@`)
	versionRegex := regexp.MustCompile(`^\s+version\s+"([^"]+)"`)

	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()

		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			currentPackage = matches[1]
		} else if matches := versionRegex.FindStringSubmatch(line); matches != nil && currentPackage != "" {
			version := matches[1]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentPackage,
				Version: version,
				Type:    artifact.TypeNpmPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "yarn",
					"source_file":     "yarn.lock",
					"resolved":        "true",
				},
			})

			currentPackage = ""
		}
	}

	return artifacts
}

// NuGet (.NET) parsers
func (d *DependencyAnalyzer) parseNuGetPackagesConfig(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	type PackageReference struct {
		Id      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	}

	type Packages struct {
		Package []PackageReference `xml:"package"`
	}

	var packages Packages
	if err := xml.NewDecoder(file).Decode(&packages); err != nil {
		return artifacts
	}

	for _, pkg := range packages.Package {
		artifacts = append(artifacts, artifact.Artifact{
			Name:    pkg.Id,
			Version: pkg.Version,
			Type:    artifact.TypeDotNetPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "nuget",
				"source_file":     "packages.config",
			},
		})
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseNuGetLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var lockData struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}

	if err := json.NewDecoder(file).Decode(&lockData); err != nil {
		return artifacts
	}

	for _, framework := range lockData.Dependencies {
		for name, dep := range framework {
			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: dep.Resolved,
				Type:    artifact.TypeDotNetPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "nuget",
					"source_file":     "packages.lock.json",
					"resolved":        "true",
				},
			})
		}
	}

	return artifacts
}

// Pub (Dart/Flutter) parsers
func (d *DependencyAnalyzer) parsePubspec(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inDependencies := false
	inDevDependencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "dependencies:" {
			inDependencies = true
			inDevDependencies = false
			continue
		} else if line == "dev_dependencies:" {
			inDependencies = false
			inDevDependencies = true
			continue
		} else if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			inDependencies = false
			inDevDependencies = false
			continue
		}

		if (inDependencies || inDevDependencies) && strings.HasPrefix(line, "  ") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					version := strings.TrimSpace(parts[1])

					depType := "production"
					if inDevDependencies {
						depType = "development"
					}

					artifacts = append(artifacts, artifact.Artifact{
						Name:    name,
						Version: version,
						Type:    artifact.TypeDartPackage,
						Path:    path,
						Source:  source,
						Metadata: map[string]string{
							"package_manager": "pub",
							"source_file":     "pubspec.yaml",
							"dependency_type": depType,
						},
					})
				}
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parsePubspecLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentPackage string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasSuffix(line, ":") && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			currentPackage = strings.TrimSuffix(strings.TrimSpace(line), ":")
		} else if strings.HasPrefix(line, "    version:") && currentPackage != "" {
			version := strings.Trim(strings.TrimPrefix(line, "    version:"), " \"'")

			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentPackage,
				Version: version,
				Type:    artifact.TypeDartPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "pub",
					"source_file":     "pubspec.lock",
					"resolved":        "true",
				},
			})

			currentPackage = ""
		}
	}

	return artifacts
}

// PyPI (Python) parsers
func (d *DependencyAnalyzer) parseRequirementsTxt(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	requirementRegex := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)([<>=!]+.*)?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		if matches := requirementRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				version = strings.TrimSpace(matches[2])
			}

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypePythonPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "pip",
					"source_file":     filepath.Base(path),
				},
			})
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parsePipfile(path string, source artifact.Source) []artifact.Artifact {
	// Pipfile is TOML format - simplified parsing for now
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inPackages := false
	inDevPackages := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[packages]" {
			inPackages = true
			inDevPackages = false
			continue
		} else if line == "[dev-packages]" {
			inPackages = false
			inDevPackages = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inPackages = false
			inDevPackages = false
			continue
		}

		if (inPackages || inDevPackages) && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

				depType := "production"
				if inDevPackages {
					depType = "development"
				}

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypePythonPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "pipenv",
						"source_file":     "Pipfile",
						"dependency_type": depType,
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parsePyprojectToml(path string, source artifact.Source) []artifact.Artifact {
	// pyproject.toml is TOML format - simplified parsing for now
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inDependencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "dependencies") && strings.Contains(line, "=") && strings.Contains(line, "[") {
			inDependencies = true
			continue
		}

		if inDependencies && line == "]" {
			inDependencies = false
			continue
		}

		if inDependencies && strings.Contains(line, "\"") {
			// Extract package from quoted string
			depRegex := regexp.MustCompile(`"([^"]+)"`)
			if matches := depRegex.FindStringSubmatch(line); matches != nil {
				requirement := matches[1]
				requirementRegex := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)([<>=!]+.*)?`)

				if reqMatches := requirementRegex.FindStringSubmatch(requirement); reqMatches != nil {
					name := reqMatches[1]
					version := ""
					if len(reqMatches) > 2 && reqMatches[2] != "" {
						version = strings.TrimSpace(reqMatches[2])
					}

					artifacts = append(artifacts, artifact.Artifact{
						Name:    name,
						Version: version,
						Type:    artifact.TypePythonPackage,
						Path:    path,
						Source:  source,
						Metadata: map[string]string{
							"package_manager": "poetry",
							"source_file":     "pyproject.toml",
						},
					})
				}
			}
		}
	}

	return artifacts
}

// RubyGems parsers
func (d *DependencyAnalyzer) parseGemfile(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	gemRegex := regexp.MustCompile(`gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := gemRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
			}

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypeRubyGem,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "bundler",
					"source_file":     "Gemfile",
				},
			})
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseGemfileLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inSpecs := false
	gemRegex := regexp.MustCompile(`^\s+([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if inSpecs && !strings.HasPrefix(line, "  ") {
			inSpecs = false
		}

		if inSpecs {
			if matches := gemRegex.FindStringSubmatch(line); matches != nil {
				name := matches[1]
				version := matches[2]

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeRubyGem,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "bundler",
						"source_file":     "Gemfile.lock",
						"resolved":        "true",
					},
				})
			}
		}
	}

	return artifacts
}

// Swift Package Manager parsers
func (d *DependencyAnalyzer) parseSwiftPackage(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`\.package\s*\(\s*url:\s*["']([^"']+)["']`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			url := matches[1]

			// Extract package name from URL
			name := filepath.Base(url)
			if strings.HasSuffix(name, ".git") {
				name = strings.TrimSuffix(name, ".git")
			}

			artifacts = append(artifacts, artifact.Artifact{
				Name:   name,
				Type:   artifact.TypeSwiftPackage,
				Path:   path,
				Source: source,
				Metadata: map[string]string{
					"package_manager": "swift",
					"source_file":     "Package.swift",
					"repository_url":  url,
				},
			})
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseSwiftPackageResolved(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	var resolvedData struct {
		Pins []struct {
			Package    string `json:"package"`
			Repository string `json:"repositoryURL"`
			State      struct {
				Revision string `json:"revision"`
				Version  string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	}

	if err := json.NewDecoder(file).Decode(&resolvedData); err != nil {
		return artifacts
	}

	for _, pin := range resolvedData.Pins {
		version := pin.State.Version
		if version == "" {
			version = pin.State.Revision[:8] // Use short revision if no version
		}

		artifacts = append(artifacts, artifact.Artifact{
			Name:    pin.Package,
			Version: version,
			Type:    artifact.TypeSwiftPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "swift",
				"source_file":     "Package.resolved",
				"resolved":        "true",
				"repository_url":  pin.Repository,
			},
		})
	}

	return artifacts
}

// Haskell parsers
func (d *DependencyAnalyzer) parseStackYaml(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inExtraDeps := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "extra-deps:" {
			inExtraDeps = true
			continue
		}

		if inExtraDeps && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, " ") {
			inExtraDeps = false
		}

		if inExtraDeps && strings.HasPrefix(line, "-") {
			dep := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			dep = strings.Trim(dep, "\"'")

			// Parse package-version format
			parts := strings.Split(dep, "-")
			if len(parts) >= 2 {
				// Last part is likely version
				version := parts[len(parts)-1]
				name := strings.Join(parts[:len(parts)-1], "-")

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeHaskellPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "stack",
						"source_file":     "stack.yaml",
					},
				})
			}
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseCabalProject(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "allow-newer:") || strings.HasPrefix(line, "constraints:") {
			constraints := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			packages := strings.Split(constraints, ",")

			for _, pkg := range packages {
				pkg = strings.TrimSpace(pkg)
				if pkg == "" {
					continue
				}

				// Extract package name and version constraint
				name := pkg
				version := ""
				if spaceIndex := strings.Index(pkg, " "); spaceIndex != -1 {
					name = strings.TrimSpace(pkg[:spaceIndex])
					version = strings.TrimSpace(pkg[spaceIndex:])
				}

				artifacts = append(artifacts, artifact.Artifact{
					Name:    name,
					Version: version,
					Type:    artifact.TypeHaskellPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "cabal",
						"source_file":     "cabal.project",
					},
				})
			}
		}
	}

	return artifacts
}

// Hex (Elixir/Erlang) parsers
func (d *DependencyAnalyzer) parseMixExs(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	depRegex := regexp.MustCompile(`\{\s*:([^,\s]+)\s*,\s*["']([^"']+)["']\s*\}`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := depRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := matches[2]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypeHexPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "hex",
					"source_file":     "mix.exs",
				},
			})
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseMixLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lockRegex := regexp.MustCompile(`"([^"]+)":\s*\{:hex,\s*:([^,]+),\s*"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := lockRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := matches[3]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    name,
				Version: version,
				Type:    artifact.TypeHexPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "hex",
					"source_file":     "mix.lock",
					"resolved":        "true",
				},
			})
		}
	}

	return artifacts
}

// Terraform parsers
func (d *DependencyAnalyzer) parseTerraformFile(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	moduleRegex := regexp.MustCompile(`module\s+"([^"]+)"\s*\{`)
	sourceRegex := regexp.MustCompile(`source\s*=\s*"([^"]+)"`)
	versionRegex := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)

	var currentModule string
	var currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := moduleRegex.FindStringSubmatch(line); matches != nil {
			currentModule = matches[1]
		} else if matches := sourceRegex.FindStringSubmatch(line); matches != nil && currentModule != "" {
			moduleSource := matches[1]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentModule,
				Version: currentVersion,
				Type:    artifact.TypeTerraformConfig,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "terraform",
					"source_file":     filepath.Base(path),
					"module_source":   moduleSource,
				},
			})

			currentModule = ""
			currentVersion = ""
		} else if matches := versionRegex.FindStringSubmatch(line); matches != nil {
			currentVersion = matches[1]
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseTerraformLock(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	providerRegex := regexp.MustCompile(`provider\s+"([^"]+)"\s*\{`)
	versionRegex := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)

	var currentProvider string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := providerRegex.FindStringSubmatch(line); matches != nil {
			currentProvider = matches[1]
		} else if matches := versionRegex.FindStringSubmatch(line); matches != nil && currentProvider != "" {
			version := matches[1]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentProvider,
				Version: version,
				Type:    artifact.TypeTerraformConfig,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "terraform",
					"source_file":     "terraform.lock.hcl",
					"resolved":        "true",
					"provider":        "true",
				},
			})

			currentProvider = ""
		}
	}

	return artifacts
}

// Linux Distribution Package Manager Implementations

// Debian/Ubuntu (dpkg/apt) implementations
func (d *DependencyAnalyzer) analyzeDebianPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseDebianPackages(path, source)
}

func (d *DependencyAnalyzer) analyzeDebianSources(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseDebianSources(path, source)
}

func (d *DependencyAnalyzer) parseDebianPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^Package:\s+(.+)$`)
	versionRegex := regexp.MustCompile(`^Version:\s+(.+)$`)
	statusRegex := regexp.MustCompile(`^Status:\s+(.+)$`)

	var currentPackage, currentVersion, currentStatus string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			currentPackage = matches[1]
		} else if matches := versionRegex.FindStringSubmatch(line); matches != nil {
			currentVersion = matches[1]
		} else if matches := statusRegex.FindStringSubmatch(line); matches != nil {
			currentStatus = matches[1]
		} else if line == "" && currentPackage != "" {
			// End of package entry
			installed := strings.Contains(currentStatus, "install ok installed")

			if installed {
				artifacts = append(artifacts, artifact.Artifact{
					Name:    currentPackage,
					Version: currentVersion,
					Type:    artifact.TypeDebianPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "dpkg",
						"status":          currentStatus,
						"distribution":    "debian",
					},
				})
			}

			currentPackage = ""
			currentVersion = ""
			currentStatus = ""
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseDebianSources(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	sourceRegex := regexp.MustCompile(`^deb(?:-src)?\s+(\S+)\s+(\S+)\s+(.*)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := sourceRegex.FindStringSubmatch(line); matches != nil && !strings.HasPrefix(line, "#") {
			url := matches[1]
			distribution := matches[2]
			components := strings.TrimSpace(matches[3])

			artifacts = append(artifacts, artifact.Artifact{
				Name:    fmt.Sprintf("apt-source-%s", distribution),
				Version: "",
				Type:    artifact.TypeDebianPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "apt",
					"repository_url":  url,
					"distribution":    distribution,
					"components":      components,
					"source_type":     "repository",
				},
			})
		}
	}

	return artifacts
}

// RPM-based (RHEL, CentOS, Fedora, SUSE) implementations
func (d *DependencyAnalyzer) analyzeRPMPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseRPMPackages(path, source)
}

func (d *DependencyAnalyzer) parseRPMPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// For RPM packages, we'll parse either a list file or actual RPM files
	if strings.HasSuffix(path, ".rpm") {
		// Single RPM file
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, ".rpm")

		// Extract name and version from RPM filename (name-version-release.arch.rpm)
		parts := strings.Split(name, "-")
		if len(parts) >= 2 {
			packageName := strings.Join(parts[:len(parts)-2], "-")
			version := parts[len(parts)-2]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    packageName,
				Version: version,
				Type:    artifact.TypeRPMPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "rpm",
					"file_type":       "rpm_package",
				},
			})
		}
	} else {
		// RPM list file - parse installed packages
		file, err := os.Open(path)
		if err != nil {
			return artifacts
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		rpmRegex := regexp.MustCompile(`^([^-]+)-([^-]+)-([^-]+)\.(\w+)$`)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if matches := rpmRegex.FindStringSubmatch(line); matches != nil {
				packageName := matches[1]
				version := matches[2]
				release := matches[3]
				arch := matches[4]

				artifacts = append(artifacts, artifact.Artifact{
					Name:    packageName,
					Version: fmt.Sprintf("%s-%s", version, release),
					Type:    artifact.TypeRPMPackage,
					Path:    path,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "rpm",
						"architecture":    arch,
						"release":         release,
					},
				})
			}
		}
	}

	return artifacts
}

// Alpine (apk) implementations
func (d *DependencyAnalyzer) analyzeAlpinePackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseAlpinePackages(path, source)
}

func (d *DependencyAnalyzer) analyzeAlpineRepositories(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseAlpineRepositories(path, source)
}

func (d *DependencyAnalyzer) parseAlpinePackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^P:(.+)$`)
	versionRegex := regexp.MustCompile(`^V:(.+)$`)

	var currentPackage, currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			currentPackage = matches[1]
		} else if matches := versionRegex.FindStringSubmatch(line); matches != nil {
			currentVersion = matches[1]
		} else if line == "" && currentPackage != "" {
			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentPackage,
				Version: currentVersion,
				Type:    artifact.TypeAlpinePackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "apk",
					"distribution":    "alpine",
				},
			})

			currentPackage = ""
			currentVersion = ""
		}
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseAlpineRepositories(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line != "" && !strings.HasPrefix(line, "#") {
			artifacts = append(artifacts, artifact.Artifact{
				Name:    fmt.Sprintf("apk-repository"),
				Version: "",
				Type:    artifact.TypeAlpinePackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "apk",
					"repository_url":  line,
					"source_type":     "repository",
				},
			})
		}
	}

	return artifacts
}

// Arch Linux (pacman) implementations
func (d *DependencyAnalyzer) analyzeArchPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseArchPackages(path, source)
}

func (d *DependencyAnalyzer) analyzeArchConfig(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseArchConfig(path, source)
}

func (d *DependencyAnalyzer) parseArchPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	// Parse pacman local database
	err := filepath.Walk(path, func(subPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() && strings.Contains(info.Name(), "-") {
			// Directory name format: packagename-version-release
			parts := strings.Split(info.Name(), "-")
			if len(parts) >= 2 {
				packageName := strings.Join(parts[:len(parts)-2], "-")
				version := parts[len(parts)-2]

				artifacts = append(artifacts, artifact.Artifact{
					Name:    packageName,
					Version: version,
					Type:    artifact.TypeArchPackage,
					Path:    subPath,
					Source:  source,
					Metadata: map[string]string{
						"package_manager": "pacman",
						"distribution":    "arch",
					},
				})
			}
		}

		return nil
	})

	if err != nil {
		return artifacts
	}

	return artifacts
}

func (d *DependencyAnalyzer) parseArchConfig(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	serverRegex := regexp.MustCompile(`^Server\s*=\s*(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := serverRegex.FindStringSubmatch(line); matches != nil && !strings.HasPrefix(line, "#") {
			serverUrl := matches[1]

			artifacts = append(artifacts, artifact.Artifact{
				Name:    "pacman-repository",
				Version: "",
				Type:    artifact.TypeArchPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "pacman",
					"repository_url":  serverUrl,
					"source_type":     "repository",
				},
			})
		}
	}

	return artifacts
}

// Gentoo (portage) implementations
func (d *DependencyAnalyzer) analyzeGentooPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseGentooPackages(path, source)
}

func (d *DependencyAnalyzer) parseGentooPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	file, err := os.Open(path)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageRegex := regexp.MustCompile(`^([^/]+)/([^-]+)-(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := packageRegex.FindStringSubmatch(line); matches != nil {
			category := matches[1]
			packageName := matches[2]
			version := matches[3]
			fullName := fmt.Sprintf("%s/%s", category, packageName)

			artifacts = append(artifacts, artifact.Artifact{
				Name:    fullName,
				Version: version,
				Type:    artifact.TypeGentooPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "portage",
					"category":        category,
					"distribution":    "gentoo",
				},
			})
		}
	}

	return artifacts
}

// Snap packages implementations
func (d *DependencyAnalyzer) analyzeSnapPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseSnapPackages(path, source)
}

func (d *DependencyAnalyzer) parseSnapPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	if strings.HasSuffix(path, ".snap") {
		// Single snap package file
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, ".snap")

		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: "",
			Type:    artifact.TypeSnapPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "snap",
				"file_type":       "snap_package",
			},
		})
	} else if filepath.Base(path) == "snap.yaml" {
		// Snap manifest file
		file, err := os.Open(path)
		if err != nil {
			return artifacts
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		nameRegex := regexp.MustCompile(`^name:\s*(.+)$`)
		versionRegex := regexp.MustCompile(`^version:\s*(.+)$`)

		var currentName, currentVersion string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if matches := nameRegex.FindStringSubmatch(line); matches != nil {
				currentName = strings.Trim(matches[1], "\"'")
			} else if matches := versionRegex.FindStringSubmatch(line); matches != nil {
				currentVersion = strings.Trim(matches[1], "\"'")
			}
		}

		if currentName != "" {
			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentName,
				Version: currentVersion,
				Type:    artifact.TypeSnapPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "snap",
					"source_file":     "snap.yaml",
				},
			})
		}
	}

	return artifacts
}

// Flatpak packages implementations
func (d *DependencyAnalyzer) analyzeFlatpakPackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseFlatpakPackages(path, source)
}

func (d *DependencyAnalyzer) parseFlatpakPackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	if strings.HasSuffix(path, ".flatpak") {
		// Single flatpak package file
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, ".flatpak")

		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: "",
			Type:    artifact.TypeFlatpakPackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "flatpak",
				"file_type":       "flatpak_package",
			},
		})
	} else if filepath.Base(path) == "metadata" && strings.Contains(path, "/var/lib/flatpak/") {
		// Flatpak metadata file
		file, err := os.Open(path)
		if err != nil {
			return artifacts
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		nameRegex := regexp.MustCompile(`^name=(.+)$`)
		versionRegex := regexp.MustCompile(`^version=(.+)$`)

		var currentName, currentVersion string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if matches := nameRegex.FindStringSubmatch(line); matches != nil {
				currentName = matches[1]
			} else if matches := versionRegex.FindStringSubmatch(line); matches != nil {
				currentVersion = matches[1]
			}
		}

		if currentName != "" {
			artifacts = append(artifacts, artifact.Artifact{
				Name:    currentName,
				Version: currentVersion,
				Type:    artifact.TypeFlatpakPackage,
				Path:    path,
				Source:  source,
				Metadata: map[string]string{
					"package_manager": "flatpak",
					"source_file":     "metadata",
				},
			})
		}
	}

	return artifacts
}

// AppImage packages implementations
func (d *DependencyAnalyzer) analyzeAppImagePackages(path string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	return d.parseAppImagePackages(path, source)
}

func (d *DependencyAnalyzer) parseAppImagePackages(path string, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	if strings.HasSuffix(strings.ToLower(path), ".appimage") {
		// AppImage file
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, filepath.Ext(name))

		// Try to extract version from filename (common patterns)
		versionRegex := regexp.MustCompile(`[_-](\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?)[_-]?`)
		var version string
		if matches := versionRegex.FindStringSubmatch(name); matches != nil {
			version = matches[1]
			// Clean up package name by removing version
			name = strings.Replace(name, matches[0], "", 1)
			name = strings.Trim(name, "_-")
		}

		artifacts = append(artifacts, artifact.Artifact{
			Name:    name,
			Version: version,
			Type:    artifact.TypeAppImagePackage,
			Path:    path,
			Source:  source,
			Metadata: map[string]string{
				"package_manager": "appimage",
				"file_type":       "appimage_package",
			},
		})
	}

	return artifacts
}
