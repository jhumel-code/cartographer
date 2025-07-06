package artifact

import (
	"context"
	"fmt"
	"time"
)

// Type represents the type of software artifact
type Type string

const (
	// Linux Distribution Package types
	TypeDebianPackage   Type = "debian-package"   // dpkg (Debian, Ubuntu)
	TypeRPMPackage      Type = "rpm-package"      // rpm (RHEL, CentOS, Fedora, SUSE)
	TypeAlpinePackage   Type = "alpine-package"   // apk (Alpine)
	TypeArchPackage     Type = "arch-package"     // pacman (Arch Linux)
	TypeGentooPackage   Type = "gentoo-package"   // portage (Gentoo)
	TypeSnapPackage     Type = "snap-package"     // snap (Universal)
	TypeFlatpakPackage  Type = "flatpak-package"  // flatpak (Universal)
	TypeAppImagePackage Type = "appimage-package" // AppImage (Universal)

	// Language Package Managers (Installed Packages/Libraries)
	TypeNpmPackage      Type = "npm-package"      // Node.js packages (installed via npm/yarn/pnpm)
	TypeYarnPackage     Type = "yarn-package"     // Node.js packages (installed via Yarn)
	TypePnpmPackage     Type = "pnpm-package"     // Node.js packages (installed via pnpm)
	TypePythonPackage   Type = "python-package"   // Python packages (pip, conda, poetry)
	TypeCondaPackage    Type = "conda-package"    // conda packages
	TypeJavaPackage     Type = "java-package"     // Java packages (Maven, Gradle)
	TypeMavenPackage    Type = "maven-package"    // Maven packages
	TypeGradlePackage   Type = "gradle-package"   // Gradle packages
	TypeGoModule        Type = "go-module"        // Go modules/packages
	TypeRustCrate       Type = "rust-crate"       // Rust crates (Cargo packages)
	TypeRubyGem         Type = "ruby-gem"         // Ruby gems (RubyGems, Bundler)
	TypePHPPackage      Type = "php-package"      // PHP packages (Composer)
	TypeDotNetPackage   Type = "dotnet-package"   // .NET packages (NuGet)
	TypeHaskellPackage  Type = "haskell-package"  // Haskell packages (Cabal, Stack)
	TypeSwiftPackage    Type = "swift-package"    // Swift packages (Swift Package Manager)
	TypeDartPackage     Type = "dart-package"     // Dart packages (pub)
	TypeCocoaPod        Type = "cocoapod"         // CocoaPods packages
	TypeCarthagePackage Type = "carthage-package" // Carthage packages
	TypeConanPackage    Type = "conan-package"    // Conan packages (C/C++)
	TypeVcpkgPackage    Type = "vcpkg-package"    // vcpkg packages (C/C++)
	TypeCRANPackage     Type = "cran-package"     // R packages (CRAN)
	TypeHexPackage      Type = "hex-package"      // Elixir/Erlang packages

	// Binary types
	TypeExecutable     Type = "executable"
	TypeSharedLibrary  Type = "shared-library"
	TypeStaticLibrary  Type = "static-library"
	TypeKernelModule   Type = "kernel-module"
	TypeSystemdService Type = "systemd-service"
	TypeInitScript     Type = "init-script"
	TypeShellScript    Type = "shell-script"
	TypePythonScript   Type = "python-script"
	TypePerlScript     Type = "perl-script"
	TypeNodeScript     Type = "node-script"

	// Configuration files
	TypeConfigFile      Type = "config-file"
	TypeEnvironmentFile Type = "environment-file"
	TypeSystemdUnit     Type = "systemd-unit"
	TypeCronJob         Type = "cron-job"
	TypeLogrotateConfig Type = "logrotate-config"
	TypeNginxConfig     Type = "nginx-config"
	TypeApacheConfig    Type = "apache-config"
	TypeSSHConfig       Type = "ssh-config"

	// Security artifacts
	TypeCertificate Type = "certificate"
	TypePrivateKey  Type = "private-key"
	TypePublicKey   Type = "public-key"
	TypeAPIKey      Type = "api-key"
	TypePassword    Type = "password"
	TypeToken       Type = "token"
	TypeSecret      Type = "secret"
	TypeKeystore    Type = "keystore"
	TypeTruststore  Type = "truststore"

	// Infrastructure as Code
	TypeDockerfile            Type = "dockerfile"
	TypeDockerCompose         Type = "docker-compose"
	TypeKubernetesManifest    Type = "kubernetes-manifest"
	TypeHelmChart             Type = "helm-chart"
	TypeTerraformConfig       Type = "terraform-config"
	TypeAnsiblePlaybook       Type = "ansible-playbook"
	TypeVagrantfile           Type = "vagrantfile"
	TypeCloudFormation        Type = "cloudformation"
	TypePulumi                Type = "pulumi"
	TypeAWSCDK                Type = "aws-cdk"
	TypeAzureResourceManager  Type = "azure-resource-manager"
	TypeGoogleCloudDeployment Type = "google-cloud-deployment"

	// Build and CI/CD
	TypeMakefile       Type = "makefile"
	TypeCMakeLists     Type = "cmake-lists"
	TypeBuildScript    Type = "build-script"
	TypeJenkinsfile    Type = "jenkinsfile"
	TypeGitHubActions  Type = "github-actions"
	TypeGitLabCI       Type = "gitlab-ci"
	TypeCircleCI       Type = "circleci"
	TypeTravisCI       Type = "travis-ci"
	TypeAzurePipelines Type = "azure-pipelines"
	TypeBuildkite      Type = "buildkite"
	TypeDroneCI        Type = "drone-ci"

	// Documentation and Legal
	TypeLicense       Type = "license"
	TypeReadme        Type = "readme"
	TypeChangelog     Type = "changelog"
	TypeDocumentation Type = "documentation"
	TypeManPage       Type = "man-page"
	TypeAPISpec       Type = "api-spec"    // OpenAPI, Swagger
	TypeSchemaFile    Type = "schema-file" // JSON Schema, GraphQL

	// Database and Data
	TypeDatabase  Type = "database"
	TypeSQLScript Type = "sql-script"
	TypeMigration Type = "migration"
	TypeDataFile  Type = "data-file"
	TypeBackup    Type = "backup"

	// Web artifacts
	TypeHTMLFile       Type = "html-file"
	TypeCSSFile        Type = "css-file"
	TypeJavaScriptFile Type = "javascript-file"
	TypeImageFile      Type = "image-file"
	TypeFontFile       Type = "font-file"

	// CycloneDX Package Manager Configuration/Manifest Files
	// These represent the files that define package dependencies, not the packages themselves

	// Node.js Ecosystem Files
	TypePackageJSON   Type = "package-json"   // package.json - Node.js project manifest
	TypePackageLock   Type = "package-lock"   // package-lock.json - npm lock file
	TypeYarnLock      Type = "yarn-lock"      // yarn.lock - Yarn lock file
	TypePnpmLock      Type = "pnpm-lock"      // pnpm-lock.yaml - pnpm lock file
	TypeNpmShrinkwrap Type = "npm-shrinkwrap" // npm-shrinkwrap.json - npm shrinkwrap file
	TypeBowerJSON     Type = "bower-json"     // bower.json - Bower components manifest

	// Python Ecosystem Files
	TypePyprojectToml   Type = "pyproject-toml"   // pyproject.toml - Python project metadata
	TypeRequirementsTxt Type = "requirements-txt" // requirements.txt - Python dependencies
	TypeSetupPy         Type = "setup-py"         // setup.py - Python package setup script
	TypePipfile         Type = "pipfile"          // Pipfile - Python dependency specification
	TypePipfileLock     Type = "pipfile-lock"     // Pipfile.lock - Python dependency lock
	TypePoetryLock      Type = "poetry-lock"      // poetry.lock - Poetry dependency lock
	TypePdmLock         Type = "pdm-lock"         // pdm.lock - PDM dependency lock
	TypeUvLock          Type = "uv-lock"          // uv.lock - uv dependency lock

	// Java Ecosystem Files
	TypePomXML      Type = "pom-xml"      // pom.xml - Maven project file
	TypeBuildGradle Type = "build-gradle" // build.gradle - Gradle build file

	// Go Ecosystem Files
	TypeGoMod     Type = "go-mod"     // go.mod - Go module file
	TypeGoSum     Type = "go-sum"     // go.sum - Go dependency checksums
	TypeGopkgLock Type = "gopkg-lock" // Gopkg.lock - dep tool lock file
	TypeGopkgToml Type = "gopkg-toml" // Gopkg.toml - dep tool manifest

	// Rust Ecosystem Files
	TypeCargoToml Type = "cargo-toml" // Cargo.toml - Rust project manifest
	TypeCargoLock Type = "cargo-lock" // Cargo.lock - Rust dependency lock

	// Ruby Ecosystem Files
	TypeGemfile     Type = "gemfile"      // Gemfile - Ruby dependency specification
	TypeGemfileLock Type = "gemfile-lock" // Gemfile.lock - Ruby dependency lock
	TypeGemspec     Type = "gemspec"      // .gemspec - Ruby gem specification

	// PHP Ecosystem Files
	TypeComposerJSON Type = "composer-json" // composer.json - PHP project manifest
	TypeComposerLock Type = "composer-lock" // composer.lock - PHP dependency lock

	// iOS/macOS Ecosystem Files
	TypePodfile         Type = "podfile"          // Podfile - CocoaPods dependency specification
	TypePodfileLock     Type = "podfile-lock"     // Podfile.lock - CocoaPods dependency lock
	TypePackageSwift    Type = "package-swift"    // Package.swift - Swift package manifest
	TypePackageResolved Type = "package-resolved" // Package.resolved - Swift dependency lock

	// Other Language Ecosystem Files
	TypeProjectClj   Type = "project-clj"   // project.clj - Clojure project file (Leiningen)
	TypeDepsEdn      Type = "deps-edn"      // deps.edn - Clojure dependencies (tools.deps)
	TypeCabalProject Type = "cabal-project" // cabal.project - Haskell project file
	TypeCabalFreeze  Type = "cabal-freeze"  // cabal.project.freeze - Haskell dependency lock
	TypeMixExs       Type = "mix-exs"       // mix.exs - Elixir project file
	TypeMixLock      Type = "mix-lock"      // mix.lock - Elixir dependency lock
	TypeConanfile    Type = "conanfile"     // conanfile.txt/py - C++ dependency specification
	TypeConanLock    Type = "conan-lock"    // conan.lock - C++ dependency lock
	TypePubspecYaml  Type = "pubspec-yaml"  // pubspec.yaml - Dart project manifest
	TypePubspecLock  Type = "pubspec-lock"  // pubspec.lock - Dart dependency lock

	// .NET Ecosystem Files
	TypeProjectAssets  Type = "project-assets"  // project.assets.json - .NET project dependencies
	TypePackagesLock   Type = "packages-lock"   // packages.lock.json - .NET dependency lock
	TypePackagesConfig Type = "packages-config" // packages.config - .NET package references
	TypePaketLock      Type = "paket-lock"      // paket.lock - Paket dependency lock
	TypeCsprojFile     Type = "csproj-file"     // .csproj - C# project file
	TypeVbprojFile     Type = "vbproj-file"     // .vbproj - VB.NET project file
	TypeFsprojFile     Type = "fsproj-file"     // .fsproj - F# project file
	TypeSlnFile        Type = "sln-file"        // .sln - Visual Studio solution file
	TypeNugetPackage   Type = "nuget-package"   // .nupkg - NuGet package file

	// Package Files (Compiled/Distributed Packages)
	TypeJarFile   Type = "jar-file"   // .jar - Java archive files
	TypeWarFile   Type = "war-file"   // .war - Java web application archive
	TypeEarFile   Type = "ear-file"   // .ear - Java enterprise application archive
	TypeWheelFile Type = "wheel-file" // .whl - Python wheel distribution
	TypeEggFile   Type = "egg-file"   // .egg - Python egg distribution (legacy)
	TypeApkFile   Type = "apk-file"   // .apk - Android application package
	TypeAabFile   Type = "aab-file"   // .aab - Android app bundle
	TypeHpiFile   Type = "hpi-file"   // .hpi - Jenkins plugin files

	// Build System Files
	TypeCMakeFile     Type = "cmake-file"     // CMakeLists.txt, *.cmake - CMake build files
	TypeMesonBuild    Type = "meson-build"    // meson.build - Meson build files
	TypeBazelFile     Type = "bazel-file"     // BUILD, BUILD.bazel - Bazel build files
	TypeBuildMill     Type = "build-mill"     // build.mill - Mill build files
	TypeSbtFile       Type = "sbt-file"       // *.sbt - SBT build files
	TypeGradleWrapper Type = "gradle-wrapper" // gradlew, gradle-wrapper.* - Gradle wrapper

	// Container and Orchestration Files
	TypeHelmValues    Type = "helm-values"     // values.yaml - Helm chart values
	TypeHelmChartYaml Type = "helm-chart-yaml" // Chart.yaml - Helm chart metadata

	// Configuration and Specification Files
	TypeOsqueryConf Type = "osquery-conf" // osquery configuration files
	TypeOpenAPISpec Type = "openapi-spec" // OpenAPI/Swagger specification files
)

// Artifact represents a software artifact found during scanning
type Artifact struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Type         Type              `json:"type"`
	Path         string            `json:"path"`
	Size         int64             `json:"size,omitempty"`
	Checksum     string            `json:"checksum,omitempty"`
	Permissions  string            `json:"permissions,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Group        string            `json:"group,omitempty"`
	ModTime      *time.Time        `json:"mod_time,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Licenses     []License         `json:"licenses,omitempty"`

	// Relationships with other artifacts
	Relationships []Relationship `json:"relationships,omitempty"`

	// Vulnerability and security information
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

	// Source information
	Source Source `json:"source"`
}

// Relationship represents a relationship between artifacts
type Relationship struct {
	Type       RelationshipType  `json:"type"`
	TargetID   string            `json:"target_id"`
	TargetName string            `json:"target_name,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// RelationshipType defines the type of relationship between artifacts
type RelationshipType string

const (
	RelationshipDependsOn  RelationshipType = "depends-on" // A depends on B
	RelationshipContains   RelationshipType = "contains"   // A contains B
	RelationshipBuilds     RelationshipType = "builds"     // A builds B
	RelationshipInstalls   RelationshipType = "installs"   // A installs B
	RelationshipConfigures RelationshipType = "configures" // A configures B
	RelationshipExtends    RelationshipType = "extends"    // A extends B
	RelationshipImplements RelationshipType = "implements" // A implements B
	RelationshipImports    RelationshipType = "imports"    // A imports B
	RelationshipIncludes   RelationshipType = "includes"   // A includes B
	RelationshipLinks      RelationshipType = "links"      // A links to B
	RelationshipProvides   RelationshipType = "provides"   // A provides B
	RelationshipRequires   RelationshipType = "requires"   // A requires B
	RelationshipConflicts  RelationshipType = "conflicts"  // A conflicts with B
	RelationshipReplaces   RelationshipType = "replaces"   // A replaces B
	RelationshipObsoletes  RelationshipType = "obsoletes"  // A obsoletes B
	RelationshipSupersedes RelationshipType = "supersedes" // A supersedes B
)

// Vulnerability represents security vulnerability information
type Vulnerability struct {
	ID          string            `json:"id"`
	CVE         string            `json:"cve,omitempty"`
	Severity    string            `json:"severity"`
	Score       float64           `json:"score,omitempty"`
	Vector      string            `json:"vector,omitempty"`
	Description string            `json:"description"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// License represents license information for an artifact
type License struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url,omitempty"`
	Expression string `json:"expression,omitempty"`
	SPDXID     string `json:"spdx_id,omitempty"`
}

// Source represents the source where an artifact was found
type Source struct {
	Type     SourceType        `json:"type"`
	Location string            `json:"location"`
	Layer    string            `json:"layer,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SourceType represents the type of source being scanned
type SourceType string

const (
	SourceTypeDockerImage SourceType = "docker-image"
	SourceTypeFilesystem  SourceType = "filesystem"
	SourceTypeArchive     SourceType = "archive"
)

// Collection represents a collection of artifacts with metadata
type Collection struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Source    Source            `json:"source"`
	ScanTime  time.Time         `json:"scan_time"`
	Artifacts []Artifact        `json:"artifacts"`
	Summary   Summary           `json:"summary"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Summary provides a high-level overview of the scan results
type Summary struct {
	TotalArtifacts  int            `json:"total_artifacts"`
	ArtifactsByType map[Type]int   `json:"artifacts_by_type"`
	LicenseCount    map[string]int `json:"license_count"`
	ScanDuration    Duration       `json:"scan_duration"`
}

// Duration wraps time.Duration to provide custom JSON marshaling
type Duration struct {
	time.Duration
}

// MarshalJSON marshals Duration to a human-readable string format
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

// UnmarshalJSON unmarshals Duration from a string format
func (d *Duration) UnmarshalJSON(data []byte) error {
	s := string(data)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("invalid duration format")
	}
	s = s[1 : len(s)-1] // Remove quotes

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// Scanner defines the interface for artifact scanners
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// SupportedTypes returns the artifact types this scanner can detect
	SupportedTypes() []Type

	// Scan scans the provided source for artifacts
	Scan(ctx context.Context, source Source) ([]Artifact, error)
}

// Repository defines the interface for storing and retrieving artifacts
type Repository interface {
	// Store saves an artifact collection
	Store(ctx context.Context, collection *Collection) error

	// Get retrieves an artifact collection by ID
	Get(ctx context.Context, id string) (*Collection, error)

	// List returns a list of stored collections
	List(ctx context.Context) ([]*Collection, error)

	// Delete removes an artifact collection
	Delete(ctx context.Context, id string) error

	// Search searches for artifacts matching the given criteria
	Search(ctx context.Context, query SearchQuery) ([]Artifact, error)
}

// SearchQuery represents search criteria for artifacts
type SearchQuery struct {
	Name     string            `json:"name,omitempty"`
	Type     Type              `json:"type,omitempty"`
	Version  string            `json:"version,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Limit    int               `json:"limit,omitempty"`
	Offset   int               `json:"offset,omitempty"`
}
