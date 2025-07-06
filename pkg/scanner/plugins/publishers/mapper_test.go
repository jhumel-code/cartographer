package publishers

import (
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

func TestVendorMapper_GetVendorInfo(t *testing.T) {
	vm := NewVendorMapper()

	tests := []struct {
		name     string
		artifact artifact.Artifact
		expected VendorInfo
	}{
		{
			name: "NPM scoped package",
			artifact: artifact.Artifact{
				Name: "@microsoft/typescript",
				Type: artifact.TypeNpmPackage,
			},
			expected: VendorInfo{
				Vendor:    "microsoft",
				Ecosystem: "npm-package",
			},
		},
		{
			name: "Maven package with groupId",
			artifact: artifact.Artifact{
				Name: "com.google.guava:guava",
				Type: artifact.TypeMavenPackage,
			},
			expected: VendorInfo{
				Vendor:    "google",
				Ecosystem: "maven-package",
			},
		},
		{
			name: "Go module from GitHub",
			artifact: artifact.Artifact{
				Name: "github.com/gorilla/mux",
				Type: artifact.TypeGoModule,
			},
			expected: VendorInfo{
				Vendor:    "gorilla",
				Ecosystem: "go-module",
			},
		},
		{
			name: "PHP Composer package",
			artifact: artifact.Artifact{
				Name: "symfony/console",
				Type: artifact.TypePHPPackage,
			},
			expected: VendorInfo{
				Vendor:    "symfony",
				Ecosystem: "php-package",
			},
		},
		{
			name: "Debian package with distribution metadata",
			artifact: artifact.Artifact{
				Name: "curl",
				Type: artifact.TypeDebianPackage,
				Metadata: map[string]string{
					"distribution": "ubuntu",
				},
			},
			expected: VendorInfo{
				Vendor:       "canonical",
				Distribution: "ubuntu",
				Ecosystem:    "debian-package",
			},
		},
		{
			name: "Well-known JavaScript package",
			artifact: artifact.Artifact{
				Name: "react",
				Type: artifact.TypeNpmPackage,
			},
			expected: VendorInfo{
				Vendor:    "facebook",
				Publisher: "Meta Platforms",
				Ecosystem: "npm-package",
			},
		},
		{
			name: "Unknown package falls back to ecosystem default",
			artifact: artifact.Artifact{
				Name: "unknown-package",
				Type: artifact.TypePythonPackage,
			},
			expected: VendorInfo{
				Vendor:    "pypi",
				Publisher: "Python Software Foundation",
				Ecosystem: "pypi",
				SourceURL: "https://pypi.org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vm.GetVendorInfo(&tt.artifact)

			if result.Vendor != tt.expected.Vendor {
				t.Errorf("Expected vendor %s, got %s", tt.expected.Vendor, result.Vendor)
			}

			if result.Ecosystem != tt.expected.Ecosystem {
				t.Errorf("Expected ecosystem %s, got %s", tt.expected.Ecosystem, result.Ecosystem)
			}

			if tt.expected.Publisher != "" && result.Publisher != tt.expected.Publisher {
				t.Errorf("Expected publisher %s, got %s", tt.expected.Publisher, result.Publisher)
			}

			if tt.expected.Distribution != "" && result.Distribution != tt.expected.Distribution {
				t.Errorf("Expected distribution %s, got %s", tt.expected.Distribution, result.Distribution)
			}

			if tt.expected.SourceURL != "" && result.SourceURL != tt.expected.SourceURL {
				t.Errorf("Expected source URL %s, got %s", tt.expected.SourceURL, result.SourceURL)
			}
		})
	}
}

func TestVendorMapper_ExtractNamespaceVendor(t *testing.T) {
	vm := NewVendorMapper()

	tests := []struct {
		name     string
		artifact artifact.Artifact
		expected string
	}{
		{
			name: "NPM scoped package",
			artifact: artifact.Artifact{
				Name: "@angular/core",
				Type: artifact.TypeNpmPackage,
			},
			expected: "angular",
		},
		{
			name: "Maven Apache Commons",
			artifact: artifact.Artifact{
				Name: "org.apache.commons:commons-lang3",
				Type: artifact.TypeMavenPackage,
			},
			expected: "apache",
		},
		{
			name: "Go module from GitHub",
			artifact: artifact.Artifact{
				Name: "github.com/gin-gonic/gin",
				Type: artifact.TypeGoModule,
			},
			expected: "gin-gonic",
		},
		{
			name: "PHP package with vendor",
			artifact: artifact.Artifact{
				Name: "laravel/framework",
				Type: artifact.TypePHPPackage,
			},
			expected: "laravel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vm.extractNamespaceVendor(&tt.artifact)
			if result.Vendor != tt.expected {
				t.Errorf("Expected vendor %s, got %s", tt.expected, result.Vendor)
			}
		})
	}
}

func TestVendorMapper_ExtractVendorFromURL(t *testing.T) {
	vm := NewVendorMapper()

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "GitHub URL",
			url:      "https://github.com/facebook/react",
			expected: "facebook",
		},
		{
			name:     "GitLab URL",
			url:      "https://gitlab.com/gitlab-org/gitlab",
			expected: "gitlab-org",
		},
		{
			name:     "Bitbucket URL",
			url:      "https://bitbucket.org/atlassian/jira",
			expected: "atlassian",
		},
		{
			name:     "Unknown hosting",
			url:      "https://example.com/some/repo",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vm.extractVendorFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("Expected vendor %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestVendorMapper_GetDistributionVendor(t *testing.T) {
	vm := NewVendorMapper()

	tests := []struct {
		name         string
		distribution string
		expected     string
	}{
		{"Debian", "debian", "debian"},
		{"Ubuntu", "ubuntu", "canonical"},
		{"RHEL", "rhel", "redhat"},
		{"CentOS", "centos", "centos"},
		{"Fedora", "fedora", "fedora"},
		{"SUSE", "suse", "suse"},
		{"Alpine", "alpine", "alpine"},
		{"Arch", "arch", "archlinux"},
		{"Unknown", "unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vm.getDistributionVendor(tt.distribution)
			if result != tt.expected {
				t.Errorf("Expected vendor %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestVendorMapper_AddCustomVendor(t *testing.T) {
	vm := NewVendorMapper()

	// Add custom package vendor
	customVendor := VendorInfo{
		Vendor:    "custom-vendor",
		Publisher: "Custom Publisher",
		Ecosystem: "npm",
	}
	vm.AddPackageVendor("custom-package", customVendor)

	// Test retrieval
	artifact := artifact.Artifact{
		Name: "custom-package",
		Type: artifact.TypeNpmPackage,
	}

	result := vm.GetVendorInfo(&artifact)
	if result.Vendor != "custom-vendor" {
		t.Errorf("Expected vendor %s, got %s", "custom-vendor", result.Vendor)
	}
	if result.Publisher != "Custom Publisher" {
		t.Errorf("Expected publisher %s, got %s", "Custom Publisher", result.Publisher)
	}
}

func TestVendorMapper_EcosystemDefaults(t *testing.T) {
	vm := NewVendorMapper()

	ecosystemTests := []struct {
		artifactType   artifact.Type
		expectedVendor string
	}{
		{artifact.TypeNpmPackage, "npmjs"},
		{artifact.TypePythonPackage, "pypi"},
		{artifact.TypeGoModule, "golang"},
		{artifact.TypeRustCrate, "rust-lang"},
		{artifact.TypeRubyGem, "rubygems"},
		{artifact.TypePHPPackage, "packagist"},
		{artifact.TypeMavenPackage, "maven"},
		{artifact.TypeDotNetPackage, "microsoft"},
		{artifact.TypeDebianPackage, "debian"},
		{artifact.TypeRPMPackage, "redhat"},
		{artifact.TypeAlpinePackage, "alpine"},
	}

	for _, tt := range ecosystemTests {
		t.Run(string(tt.artifactType), func(t *testing.T) {
			artifact := artifact.Artifact{
				Name: "test-package",
				Type: tt.artifactType,
			}

			result := vm.GetVendorInfo(&artifact)
			if result.Vendor != tt.expectedVendor {
				t.Errorf("Expected vendor %s for %s, got %s",
					tt.expectedVendor, tt.artifactType, result.Vendor)
			}
		})
	}
}
