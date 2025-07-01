package artifact

import (
	"context"
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

	// Language Package Managers
	TypeNpmPackage      Type = "npm-package"      // Node.js
	TypeYarnPackage     Type = "yarn-package"     // Node.js (Yarn)
	TypePnpmPackage     Type = "pnpm-package"     // Node.js (pnpm)
	TypePythonPackage   Type = "python-package"   // pip, conda, poetry
	TypeCondaPackage    Type = "conda-package"    // conda
	TypeJavaPackage     Type = "java-package"     // Maven, Gradle
	TypeMavenPackage    Type = "maven-package"    // Maven
	TypeGradlePackage   Type = "gradle-package"   // Gradle
	TypeGoModule        Type = "go-module"        // Go modules
	TypeRustCrate       Type = "rust-crate"       // Cargo
	TypeRubyGem         Type = "ruby-gem"         // RubyGems, Bundler
	TypePHPPackage      Type = "php-package"      // Composer
	TypeDotNetPackage   Type = "dotnet-package"   // NuGet
	TypeHaskellPackage  Type = "haskell-package"  // Cabal, Stack
	TypeSwiftPackage    Type = "swift-package"    // Swift Package Manager
	TypeDartPackage     Type = "dart-package"     // pub
	TypeCocoaPod        Type = "cocoapod"         // CocoaPods
	TypeCarthagePackage Type = "carthage-package" // Carthage
	TypeConanPackage    Type = "conan-package"    // Conan (C/C++)
	TypeVcpkgPackage    Type = "vcpkg-package"    // vcpkg (C/C++)
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
	ScanDuration    time.Duration  `json:"scan_duration"`
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
