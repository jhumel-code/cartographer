package license

import (
	"context"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// SPDX license identifier constants
const (
	SPDXMIT        = "MIT"
	SPDXApache20   = "Apache-2.0"
	SPDXBSD3Clause = "BSD-3-Clause"
	SPDXBSD2Clause = "BSD-2-Clause"
	SPDXGPL30      = "GPL-3.0"
	SPDXGPL20      = "GPL-2.0"
	SPDXLGPL30     = "LGPL-3.0"
	SPDXLGPL21     = "LGPL-2.1"
	SPDXMPL20      = "MPL-2.0"
	SPDXISC        = "ISC"
	SPDXUnlicense  = "Unlicense"
	SPDXCC01       = "CC0-1.0"
	SPDXWTFPL      = "WTFPL"
)

// SPDXLicenseMappingPlugin enhances license artifacts with SPDX identifiers
type SPDXLicenseMappingPlugin struct {
	spdxMapping map[string]string
}

// NewSPDXLicenseMappingPlugin creates a new SPDX license mapping plugin
func NewSPDXLicenseMappingPlugin() *SPDXLicenseMappingPlugin {
	plugin := &SPDXLicenseMappingPlugin{
		spdxMapping: make(map[string]string),
	}

	// Initialize common license mappings
	plugin.initializeLicenseMappings()

	return plugin
}

// Name returns the plugin name
func (p *SPDXLicenseMappingPlugin) Name() string {
	return "spdx-license-mapping-plugin"
}

// Priority returns the execution priority (lower numbers execute first)
func (p *SPDXLicenseMappingPlugin) Priority() int {
	return 20 // Run after vendor mapping but before dependency mapping
}

// SupportedTypes returns the license types this plugin can enhance
func (p *SPDXLicenseMappingPlugin) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeLicense,
		// Also enhance packages that might have license information
		artifact.TypeNpmPackage,
		artifact.TypePythonPackage,
		artifact.TypeMavenPackage,
		artifact.TypeGoModule,
		artifact.TypeRustCrate,
		artifact.TypeRubyGem,
		artifact.TypePHPPackage,
		artifact.TypeDotNetPackage,
	}
}

// Process enhances artifacts with SPDX license identifiers
func (p *SPDXLicenseMappingPlugin) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	enhancedArtifacts := make([]artifact.Artifact, 0, len(artifacts))

	for _, art := range artifacts {
		enhanced := art

		// Process licenses for license artifacts
		if art.Type == artifact.TypeLicense {
			enhanced = p.enhanceLicenseArtifact(enhanced)
		} else {
			// Process package licenses
			enhanced = p.enhancePackageLicenses(enhanced)
		}

		enhancedArtifacts = append(enhancedArtifacts, enhanced)
	}

	return enhancedArtifacts, nil
}

// enhanceLicenseArtifact enhances a license artifact with SPDX information
func (p *SPDXLicenseMappingPlugin) enhanceLicenseArtifact(art artifact.Artifact) artifact.Artifact {
	if art.Metadata == nil {
		art.Metadata = make(map[string]string)
	}

	// Try to map the license type to SPDX
	if licenseType, exists := art.Metadata["license_type"]; exists {
		if spdxID := p.mapToSPDX(licenseType); spdxID != "" {
			art.Metadata["spdx_id"] = spdxID
		}
	}

	return art
}

// enhancePackageLicenses enhances package artifacts with SPDX license information
func (p *SPDXLicenseMappingPlugin) enhancePackageLicenses(art artifact.Artifact) artifact.Artifact {
	if len(art.Licenses) == 0 {
		return art
	}

	enhancedLicenses := make([]artifact.License, 0, len(art.Licenses))

	for _, license := range art.Licenses {
		enhanced := license

		// Map license ID to SPDX if possible
		if spdxID := p.mapToSPDX(license.ID); spdxID != "" {
			enhanced.SPDXID = spdxID
		}

		enhancedLicenses = append(enhancedLicenses, enhanced)
	}

	art.Licenses = enhancedLicenses
	return art
}

// mapToSPDX maps a license identifier to its SPDX equivalent
func (p *SPDXLicenseMappingPlugin) mapToSPDX(licenseID string) string {
	// Normalize the license ID
	normalized := strings.ToLower(strings.TrimSpace(licenseID))

	if spdxID, exists := p.spdxMapping[normalized]; exists {
		return spdxID
	}

	// If no exact match, try partial matching for common patterns
	return p.findPartialMatch(normalized)
}

// findPartialMatch tries to find SPDX ID based on partial matching
func (p *SPDXLicenseMappingPlugin) findPartialMatch(licenseID string) string {
	if strings.Contains(licenseID, "mit") {
		return SPDXMIT
	}
	if strings.Contains(licenseID, "apache") && strings.Contains(licenseID, "2") {
		return SPDXApache20
	}
	if strings.Contains(licenseID, "bsd") {
		if strings.Contains(licenseID, "3") {
			return SPDXBSD3Clause
		}
		if strings.Contains(licenseID, "2") {
			return SPDXBSD2Clause
		}
	}
	if strings.Contains(licenseID, "gpl") {
		if strings.Contains(licenseID, "3") {
			return SPDXGPL30
		}
		if strings.Contains(licenseID, "2") {
			return SPDXGPL20
		}
	}

	return ""
}

// initializeLicenseMappings sets up common license mappings
func (p *SPDXLicenseMappingPlugin) initializeLicenseMappings() {
	p.spdxMapping = map[string]string{
		// MIT variations
		"mit":         SPDXMIT,
		"mit license": SPDXMIT,
		"mit licence": SPDXMIT,

		// Apache variations
		"apache 2.0":         SPDXApache20,
		"apache license 2.0": SPDXApache20,
		"apache licence 2.0": SPDXApache20,
		"apache-2.0":         SPDXApache20,
		"apache":             SPDXApache20,

		// BSD variations
		"bsd":                    SPDXBSD3Clause,
		"bsd license":            SPDXBSD3Clause,
		"bsd 3-clause":           SPDXBSD3Clause,
		"bsd 2-clause":           SPDXBSD2Clause,
		"new bsd license":        SPDXBSD3Clause,
		"simplified bsd license": SPDXBSD2Clause,

		// GPL variations
		"gpl":                        SPDXGPL30,
		"gpl 3.0":                    SPDXGPL30,
		"gpl 2.0":                    SPDXGPL20,
		"gnu gpl":                    SPDXGPL30,
		"gnu general public license": SPDXGPL30,

		// LGPL variations
		"lgpl":     SPDXLGPL30,
		"lgpl 3.0": SPDXLGPL30,
		"lgpl 2.1": SPDXLGPL21,

		// Other common licenses
		"isc":           SPDXISC,
		"mozilla":       SPDXMPL20,
		"mpl":           SPDXMPL20,
		"mpl 2.0":       SPDXMPL20,
		"unlicense":     SPDXUnlicense,
		"public domain": SPDXUnlicense,
		"cc0":           SPDXCC01,
		"wtfpl":         SPDXWTFPL,
	}
}
