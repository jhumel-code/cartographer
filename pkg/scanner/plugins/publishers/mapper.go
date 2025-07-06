package publishers

import (
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// Common vendor/publisher constants
const (
	VendorGoogle      = "google"
	VendorMicrosoft   = "microsoft"
	VendorApache      = "apache"
	VendorRustLang    = "rust-lang"
	VendorFacebook    = "facebook"
	VendorDebian      = "debian"
	VendorRedHat      = "redhat"
	VendorScikitLearn = "scikit-learn"

	PublisherGoogleLLC    = "Google LLC"
	PublisherMicrosoft    = "Microsoft Corporation"
	PublisherApacheSF     = "Apache Software Foundation"
	PublisherRustFound    = "Rust Foundation"
	PublisherMetaPlatform = "Meta Platforms"
	PublisherScikitLearn  = "scikit-learn"
)

// VendorInfo contains vendor/publisher information for CPE generation
type VendorInfo struct {
	// Vendor is the primary vendor/organization identifier
	Vendor string `json:"vendor"`
	// Publisher is an alternative vendor name (may differ from Vendor)
	Publisher string `json:"publisher,omitempty"`
	// SourceURL is the primary source/homepage URL
	SourceURL string `json:"source_url,omitempty"`
	// RepositoryURL is the source code repository URL
	RepositoryURL string `json:"repository_url,omitempty"`
	// Distribution is the Linux distribution (for OS packages)
	Distribution string `json:"distribution,omitempty"`
	// Ecosystem is the package ecosystem identifier
	Ecosystem string `json:"ecosystem,omitempty"`
}

// VendorMapper provides vendor information for artifacts to support CPE generation
type VendorMapper struct {
	// Package-specific vendor mappings
	packageVendors map[string]VendorInfo
	// Ecosystem default vendors
	ecosystemVendors map[artifact.Type]VendorInfo
}

// NewVendorMapper creates a new vendor mapper with predefined mappings
func NewVendorMapper() *VendorMapper {
	vm := &VendorMapper{
		packageVendors:   make(map[string]VendorInfo),
		ecosystemVendors: make(map[artifact.Type]VendorInfo),
	}

	vm.initializeEcosystemVendors()
	vm.initializeWellKnownPackageVendors()

	return vm
}

// GetVendorInfo returns vendor information for an artifact
func (vm *VendorMapper) GetVendorInfo(art *artifact.Artifact) VendorInfo {
	// First check for package-specific vendor mapping
	if vendor, exists := vm.packageVendors[strings.ToLower(art.Name)]; exists {
		return vm.enrichVendorInfo(vendor, art)
	}

	// Check for namespace-based vendor (e.g., @microsoft/package-name, com.google.*)
	if vendor := vm.extractNamespaceVendor(art); vendor.Vendor != "" {
		return vm.enrichVendorInfo(vendor, art)
	}

	// Extract from metadata (before ecosystem defaults)
	if vendor := vm.extractMetadataVendor(art); vendor.Vendor != "" {
		return vm.enrichVendorInfo(vendor, art)
	}

	// Fall back to ecosystem default
	if vendor, exists := vm.ecosystemVendors[art.Type]; exists {
		return vm.enrichVendorInfo(vendor, art)
	}

	// Default fallback
	return VendorInfo{
		Vendor:    vm.getDefaultVendor(art.Type),
		Ecosystem: string(art.Type),
	}
}

// initializeEcosystemVendors sets up default vendors for each package ecosystem
func (vm *VendorMapper) initializeEcosystemVendors() {
	vm.ecosystemVendors = map[artifact.Type]VendorInfo{
		// Linux Distribution Packages
		artifact.TypeDebianPackage: {
			Vendor:       VendorDebian,
			Publisher:    "Debian Project",
			Distribution: "debian",
			Ecosystem:    "debian",
		},
		artifact.TypeRPMPackage: {
			Vendor:    VendorRedHat, // Default, often overridden by distribution
			Publisher: "Red Hat",
			Ecosystem: "rpm",
		},
		artifact.TypeAlpinePackage: {
			Vendor:       "alpine",
			Publisher:    "Alpine Linux",
			Distribution: "alpine",
			Ecosystem:    "alpine",
		},
		artifact.TypeArchPackage: {
			Vendor:       "archlinux",
			Publisher:    "Arch Linux",
			Distribution: "arch",
			Ecosystem:    "arch",
		},
		artifact.TypeGentooPackage: {
			Vendor:       "gentoo",
			Publisher:    "Gentoo Foundation",
			Distribution: "gentoo",
			Ecosystem:    "gentoo",
		},
		artifact.TypeSnapPackage: {
			Vendor:    "canonical",
			Publisher: "Canonical",
			Ecosystem: "snap",
		},
		artifact.TypeFlatpakPackage: {
			Vendor:    "flathub",
			Publisher: "Flathub",
			Ecosystem: "flatpak",
		},

		// Language Package Managers
		artifact.TypeNpmPackage: {
			Vendor:    "npmjs",
			Publisher: "npm, Inc.",
			Ecosystem: "npm",
			SourceURL: "https://www.npmjs.com",
		},
		artifact.TypePythonPackage: {
			Vendor:    "pypi",
			Publisher: "Python Software Foundation",
			Ecosystem: "pypi",
			SourceURL: "https://pypi.org",
		},
		artifact.TypeGoModule: {
			Vendor:    "golang",
			Publisher: "Go Team",
			Ecosystem: "go",
			SourceURL: "https://pkg.go.dev",
		},
		artifact.TypeRustCrate: {
			Vendor:    VendorRustLang,
			Publisher: PublisherRustFound,
			Ecosystem: "cargo",
			SourceURL: "https://crates.io",
		},
		artifact.TypeRubyGem: {
			Vendor:    "rubygems",
			Publisher: "Ruby Central",
			Ecosystem: "rubygems",
			SourceURL: "https://rubygems.org",
		},
		artifact.TypePHPPackage: {
			Vendor:    "packagist",
			Publisher: "Packagist",
			Ecosystem: "composer",
			SourceURL: "https://packagist.org",
		},
		artifact.TypeMavenPackage: {
			Vendor:    "maven",
			Publisher: PublisherApacheSF,
			Ecosystem: "maven",
			SourceURL: "https://central.sonatype.com",
		},
		artifact.TypeGradlePackage: {
			Vendor:    "gradle",
			Publisher: "Gradle Inc.",
			Ecosystem: "gradle",
		},
		artifact.TypeDotNetPackage: {
			Vendor:    VendorMicrosoft,
			Publisher: PublisherMicrosoft,
			Ecosystem: "nuget",
			SourceURL: "https://www.nuget.org",
		},
		artifact.TypeSwiftPackage: {
			Vendor:    "apple",
			Publisher: "Apple Inc.",
			Ecosystem: "swift",
		},
		artifact.TypeDartPackage: {
			Vendor:    VendorGoogle,
			Publisher: PublisherGoogleLLC,
			Ecosystem: "pub",
			SourceURL: "https://pub.dev",
		},
		artifact.TypeCocoaPod: {
			Vendor:    "cocoapods",
			Publisher: "CocoaPods",
			Ecosystem: "cocoapods",
			SourceURL: "https://cocoapods.org",
		},
		artifact.TypeConanPackage: {
			Vendor:    "conan",
			Publisher: "JFrog",
			Ecosystem: "conan",
			SourceURL: "https://conan.io",
		},
		artifact.TypeCRANPackage: {
			Vendor:    "r-project",
			Publisher: "R Foundation",
			Ecosystem: "cran",
			SourceURL: "https://cran.r-project.org",
		},
		artifact.TypeHexPackage: {
			Vendor:    "hex",
			Publisher: "Hex.pm",
			Ecosystem: "hex",
			SourceURL: "https://hex.pm",
		},
		artifact.TypeHaskellPackage: {
			Vendor:    "haskell",
			Publisher: "Haskell Foundation",
			Ecosystem: "hackage",
			SourceURL: "https://hackage.haskell.org",
		},
		artifact.TypeTerraformConfig: {
			Vendor:    "hashicorp",
			Publisher: "HashiCorp",
			Ecosystem: "terraform",
		},
	}
}

// initializeWellKnownPackageVendors sets up vendor mappings for well-known packages
func (vm *VendorMapper) initializeWellKnownPackageVendors() {
	vm.addJavaScriptVendors()
	vm.addPythonVendors()
	vm.addGoVendors()
	vm.addJavaVendors()
	vm.addRustVendors()
	vm.addPHPVendors()
	vm.addRubyVendors()
}

func (vm *VendorMapper) addJavaScriptVendors() {
	vendors := map[string]VendorInfo{
		"react":         {Vendor: VendorFacebook, Publisher: PublisherMetaPlatform},
		"angular":       {Vendor: VendorGoogle, Publisher: PublisherGoogleLLC},
		"vue":           {Vendor: "vuejs", Publisher: "Vue.js"},
		"express":       {Vendor: "expressjs", Publisher: "Express.js"},
		"lodash":        {Vendor: "lodash", Publisher: "Lodash"},
		"jquery":        {Vendor: "jquery", Publisher: "jQuery Foundation"},
		"typescript":    {Vendor: VendorMicrosoft, Publisher: PublisherMicrosoft},
		"webpack":       {Vendor: "webpack", Publisher: "Webpack"},
		"babel":         {Vendor: "babel", Publisher: "Babel"},
		"eslint":        {Vendor: "eslint", Publisher: "ESLint"},
		"prettier":      {Vendor: "prettier", Publisher: "Prettier"},
		"jest":          {Vendor: VendorFacebook, Publisher: PublisherMetaPlatform},
		"moment":        {Vendor: "moment", Publisher: "Moment.js"},
		"axios":         {Vendor: "axios", Publisher: "Axios"},
		"next":          {Vendor: "vercel", Publisher: "Vercel"},
		"@types/node":   {Vendor: VendorMicrosoft, Publisher: PublisherMicrosoft},
		"@angular/core": {Vendor: VendorGoogle, Publisher: PublisherGoogleLLC},
		"@babel/core":   {Vendor: "babel", Publisher: "Babel"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addPythonVendors() {
	vendors := map[string]VendorInfo{
		"django":          {Vendor: "django", Publisher: "Django Software Foundation"},
		"flask":           {Vendor: "pallets", Publisher: "Pallets"},
		"requests":        {Vendor: "psf", Publisher: "Python Software Foundation"},
		"numpy":           {Vendor: "numpy", Publisher: "NumPy"},
		"pandas":          {Vendor: "pandas-dev", Publisher: "pandas"},
		"tensorflow":      {Vendor: VendorGoogle, Publisher: PublisherGoogleLLC},
		"pytorch":         {Vendor: "pytorch", Publisher: "PyTorch Foundation"},
		VendorScikitLearn: {Vendor: VendorScikitLearn, Publisher: PublisherScikitLearn},
		"matplotlib":      {Vendor: "matplotlib", Publisher: "Matplotlib"},
		"scipy":           {Vendor: "scipy", Publisher: "SciPy"},
		"pillow":          {Vendor: "python-pillow", Publisher: "Pillow"},
		"sqlalchemy":      {Vendor: "sqlalchemy", Publisher: "SQLAlchemy"},
		"boto3":           {Vendor: "amazon", Publisher: "Amazon Web Services"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addGoVendors() {
	vendors := map[string]VendorInfo{
		"github.com/gorilla/mux":              {Vendor: "gorilla", Publisher: "Gorilla Web Toolkit"},
		"github.com/gin-gonic/gin":            {Vendor: "gin-gonic", Publisher: "Gin"},
		"github.com/sirupsen/logrus":          {Vendor: "sirupsen", Publisher: "Simon Eskildsen"},
		"github.com/stretchr/testify":         {Vendor: "stretchr", Publisher: "Stretchr"},
		"github.com/go-sql-driver/mysql":      {Vendor: "go-sql-driver", Publisher: "Go MySQL Driver"},
		"github.com/lib/pq":                   {Vendor: "lib", Publisher: "PostgreSQL driver"},
		"google.golang.org/grpc":              {Vendor: VendorGoogle, Publisher: PublisherGoogleLLC},
		"k8s.io/client-go":                    {Vendor: "kubernetes", Publisher: "Kubernetes"},
		"github.com/prometheus/client_golang": {Vendor: "prometheus", Publisher: "Prometheus"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addJavaVendors() {
	vendors := map[string]VendorInfo{
		"org.springframework:spring-core":         {Vendor: "pivotal", Publisher: "VMware Tanzu"},
		"org.apache.commons:commons-lang3":        {Vendor: VendorApache, Publisher: PublisherApacheSF},
		"com.google.guava:guava":                  {Vendor: VendorGoogle, Publisher: PublisherGoogleLLC},
		"junit:junit":                             {Vendor: "junit", Publisher: "JUnit"},
		"org.slf4j:slf4j-api":                     {Vendor: "slf4j", Publisher: "SLF4J"},
		"ch.qos.logback:logback-classic":          {Vendor: "qos", Publisher: "QOS.ch"},
		"org.apache.httpcomponents:httpclient":    {Vendor: VendorApache, Publisher: PublisherApacheSF},
		"com.fasterxml.jackson.core:jackson-core": {Vendor: "fasterxml", Publisher: "FasterXML"},
		"org.hibernate:hibernate-core":            {Vendor: "hibernate", Publisher: "Red Hat"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addRustVendors() {
	vendors := map[string]VendorInfo{
		"serde":     {Vendor: "serde-rs", Publisher: "Serde"},
		"tokio":     {Vendor: "tokio-rs", Publisher: "Tokio"},
		"clap":      {Vendor: "clap-rs", Publisher: "clap"},
		"reqwest":   {Vendor: "seanmonstar", Publisher: "Sean McArthur"},
		"actix-web": {Vendor: "actix", Publisher: "Actix"},
		"diesel":    {Vendor: "diesel-rs", Publisher: "Diesel"},
		"regex":     {Vendor: VendorRustLang, Publisher: "Rust"},
		"log":       {Vendor: VendorRustLang, Publisher: "Rust"},
		"rand":      {Vendor: "rust-random", Publisher: "Rust Random"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addPHPVendors() {
	vendors := map[string]VendorInfo{
		"symfony/console":   {Vendor: "symfony", Publisher: "Symfony"},
		"laravel/framework": {Vendor: "laravel", Publisher: "Laravel"},
		"guzzlehttp/guzzle": {Vendor: "guzzle", Publisher: "Guzzle"},
		"monolog/monolog":   {Vendor: "monolog", Publisher: "Monolog"},
		"phpunit/phpunit":   {Vendor: "phpunit", Publisher: "PHPUnit"},
		"doctrine/orm":      {Vendor: "doctrine", Publisher: "Doctrine Project"},
		"twig/twig":         {Vendor: "twig", Publisher: "Twig"},
		"composer/composer": {Vendor: "composer", Publisher: "Composer"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

func (vm *VendorMapper) addRubyVendors() {
	vendors := map[string]VendorInfo{
		"rails":        {Vendor: "rails", Publisher: "Ruby on Rails"},
		"devise":       {Vendor: "heartcombo", Publisher: "Heartcombo"},
		"sidekiq":      {Vendor: "mperham", Publisher: "Mike Perham"},
		"rspec":        {Vendor: "rspec", Publisher: "RSpec"},
		"puma":         {Vendor: "puma", Publisher: "Puma"},
		"nokogiri":     {Vendor: "sparklemotion", Publisher: "Sparkle Motion"},
		"activerecord": {Vendor: "rails", Publisher: "Ruby on Rails"},
		"bundler":      {Vendor: "rubygems", Publisher: "Ruby Central"},
	}

	for name, vendor := range vendors {
		vm.packageVendors[name] = vendor
	}
}

// extractNamespaceVendor extracts vendor from package namespace/scope
func (vm *VendorMapper) extractNamespaceVendor(art *artifact.Artifact) VendorInfo {
	name := art.Name

	// NPM scoped packages (@vendor/package)
	if vendor := vm.extractNpmScopedVendor(name, art.Type); vendor.Vendor != "" {
		return vendor
	}

	// Maven/Java groupId:artifactId
	if vendor := vm.extractMavenVendor(name, art.Type); vendor.Vendor != "" {
		return vendor
	}

	// Go modules (domain.com/org/package)
	if vendor := vm.extractGoVendor(name, art.Type); vendor.Vendor != "" {
		return vendor
	}

	// PHP Composer vendor/package
	if vendor := vm.extractPHPVendor(name, art.Type); vendor.Vendor != "" {
		return vendor
	}

	// Gentoo category/package
	if vendor := vm.extractGentooVendor(name, art.Type); vendor.Vendor != "" {
		return vendor
	}

	return VendorInfo{}
}

func (vm *VendorMapper) extractNpmScopedVendor(name string, artType artifact.Type) VendorInfo {
	if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			vendor := strings.TrimPrefix(parts[0], "@")
			return VendorInfo{
				Vendor:    vendor,
				Ecosystem: string(artType),
			}
		}
	}
	return VendorInfo{}
}

func (vm *VendorMapper) extractMavenVendor(name string, artType artifact.Type) VendorInfo {
	if strings.Contains(name, ":") && artType == artifact.TypeMavenPackage {
		parts := strings.Split(name, ":")
		if len(parts) >= 2 {
			groupId := parts[0]

			// Extract vendor from reverse domain notation
			if strings.Contains(groupId, ".") {
				domainParts := strings.Split(groupId, ".")
				if len(domainParts) >= 2 {
					// For com.google.* -> google, org.apache.* -> apache
					return VendorInfo{
						Vendor:    domainParts[1],
						Ecosystem: string(artType),
					}
				}
			}

			return VendorInfo{
				Vendor:    groupId,
				Ecosystem: string(artType),
			}
		}
	}
	return VendorInfo{}
}

func (vm *VendorMapper) extractGoVendor(name string, artType artifact.Type) VendorInfo {
	if artType == artifact.TypeGoModule && strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			// For github.com/vendor/repo -> vendor
			if strings.Contains(parts[0], ".") && len(parts) >= 3 {
				return VendorInfo{
					Vendor:    parts[1],
					Ecosystem: string(artType),
				}
			}
		}
	}
	return VendorInfo{}
}

func (vm *VendorMapper) extractPHPVendor(name string, artType artifact.Type) VendorInfo {
	if artType == artifact.TypePHPPackage && strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			return VendorInfo{
				Vendor:    parts[0],
				Ecosystem: string(artType),
			}
		}
	}
	return VendorInfo{}
}

func (vm *VendorMapper) extractGentooVendor(name string, artType artifact.Type) VendorInfo {
	if artType == artifact.TypeGentooPackage && strings.Contains(name, "/") {
		return VendorInfo{
			Vendor:       "gentoo",
			Publisher:    "Gentoo Foundation",
			Distribution: "gentoo",
			Ecosystem:    "gentoo",
		}
	}
	return VendorInfo{}
}

// extractMetadataVendor extracts vendor information from artifact metadata
func (vm *VendorMapper) extractMetadataVendor(art *artifact.Artifact) VendorInfo {
	if art.Metadata == nil {
		return VendorInfo{}
	}

	vendor := VendorInfo{Ecosystem: string(art.Type)}

	vendor = vm.extractDistributionInfo(vendor, art.Metadata)
	vendor = vm.extractPublisherInfo(vendor, art.Metadata)
	vendor = vm.extractURLInfo(vendor, art.Metadata)
	vendor = vm.extractRPMSpecificInfo(vendor, art)

	return vendor
}

func (vm *VendorMapper) extractDistributionInfo(vendor VendorInfo, metadata map[string]string) VendorInfo {
	if dist, exists := metadata["distribution"]; exists {
		vendor.Distribution = dist
		vendor.Vendor = vm.getDistributionVendor(dist)
	}
	return vendor
}

func (vm *VendorMapper) extractPublisherInfo(vendor VendorInfo, metadata map[string]string) VendorInfo {
	if publisher, exists := metadata["publisher"]; exists {
		vendor.Publisher = publisher
	}
	if maintainer, exists := metadata["maintainer"]; exists {
		vendor.Publisher = maintainer
	}
	return vendor
}

func (vm *VendorMapper) extractURLInfo(vendor VendorInfo, metadata map[string]string) VendorInfo {
	if repoURL, exists := metadata["repository_url"]; exists {
		vendor.RepositoryURL = repoURL
		if extractedVendor := vm.extractVendorFromURL(repoURL); extractedVendor != "" {
			vendor.Vendor = extractedVendor
		}
	}
	if sourceURL, exists := metadata["source_url"]; exists {
		vendor.SourceURL = sourceURL
	}
	return vendor
}

func (vm *VendorMapper) extractRPMSpecificInfo(vendor VendorInfo, art *artifact.Artifact) VendorInfo {
	if art.Type == artifact.TypeRPMPackage && art.Metadata != nil {
		if arch, exists := art.Metadata["architecture"]; exists && arch != "" {
			// Common RPM distributions based on architecture patterns
			if strings.Contains(arch, "el") {
				vendor.Vendor = VendorRedHat
				vendor.Distribution = "rhel"
			} else if strings.Contains(arch, "fc") {
				vendor.Vendor = "fedora"
				vendor.Distribution = "fedora"
			} else if strings.Contains(arch, "suse") {
				vendor.Vendor = "suse"
				vendor.Distribution = "suse"
			}
		}
	}
	return vendor
}

// extractVendorFromURL extracts vendor information from repository URLs
func (vm *VendorMapper) extractVendorFromURL(url string) string {
	url = strings.ToLower(url)

	// GitHub patterns
	if vendor := vm.extractFromGitHost(url, "github.com"); vendor != "" {
		return vendor
	}

	// GitLab patterns
	if vendor := vm.extractFromGitHost(url, "gitlab.com"); vendor != "" {
		return vendor
	}

	// Other Git hosting patterns
	gitHosts := []string{"bitbucket.org", "sourceforge.net", "codeberg.org"}
	for _, host := range gitHosts {
		if vendor := vm.extractFromGitHost(url, host); vendor != "" {
			return vendor
		}
	}

	return ""
}

func (vm *VendorMapper) extractFromGitHost(url, host string) string {
	if strings.Contains(url, host) {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if strings.Contains(part, host) && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

// getDistributionVendor maps Linux distribution names to vendor identifiers
func (vm *VendorMapper) getDistributionVendor(distribution string) string {
	distMap := map[string]string{
		"debian":   VendorDebian,
		"ubuntu":   "canonical",
		"rhel":     VendorRedHat,
		"centos":   "centos",
		"fedora":   "fedora",
		"suse":     "suse",
		"opensuse": "suse",
		"alpine":   "alpine",
		"arch":     "archlinux",
		"gentoo":   "gentoo",
		"mint":     "linuxmint",
		"kali":     "kali",
		"manjaro":  "manjaro",
	}

	if vendor, exists := distMap[strings.ToLower(distribution)]; exists {
		return vendor
	}

	return distribution
}

// getDefaultVendor provides a fallback vendor for unknown package types
func (vm *VendorMapper) getDefaultVendor(artType artifact.Type) string {
	// Use ecosystem name as default vendor
	typeStr := string(artType)

	// Remove common suffixes
	typeStr = strings.TrimSuffix(typeStr, "-package")
	typeStr = strings.TrimSuffix(typeStr, "-module")
	typeStr = strings.TrimSuffix(typeStr, "-crate")
	typeStr = strings.TrimSuffix(typeStr, "-gem")

	return typeStr
}

// enrichVendorInfo adds additional context to vendor information
func (vm *VendorMapper) enrichVendorInfo(vendor VendorInfo, art *artifact.Artifact) VendorInfo {
	// Set ecosystem if not present
	if vendor.Ecosystem == "" {
		vendor.Ecosystem = string(art.Type)
	}

	vendor = vm.enrichFromMetadata(vendor, art.Metadata)

	return vendor
}

func (vm *VendorMapper) enrichFromMetadata(vendor VendorInfo, metadata map[string]string) VendorInfo {
	if metadata == nil {
		return vendor
	}

	if vendor.RepositoryURL == "" {
		if repoURL, exists := metadata["repository_url"]; exists {
			vendor.RepositoryURL = repoURL
		}
	}

	if vendor.SourceURL == "" {
		if sourceURL, exists := metadata["source_url"]; exists {
			vendor.SourceURL = sourceURL
		}
	}

	if vendor.Distribution == "" {
		if dist, exists := metadata["distribution"]; exists {
			vendor.Distribution = dist
		}
	}

	return vendor
}

// AddPackageVendor allows adding custom vendor mappings for specific packages
func (vm *VendorMapper) AddPackageVendor(packageName string, vendor VendorInfo) {
	vm.packageVendors[strings.ToLower(packageName)] = vendor
}

// AddEcosystemVendor allows adding custom vendor mappings for ecosystem types
func (vm *VendorMapper) AddEcosystemVendor(artType artifact.Type, vendor VendorInfo) {
	vm.ecosystemVendors[artType] = vendor
}
