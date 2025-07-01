package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// LicenseAnalyzer scans for license files and documentation
type LicenseAnalyzer struct {
	licensePatterns map[string]*regexp.Regexp
}

// NewLicenseAnalyzer creates a new license analyzer
func NewLicenseAnalyzer() *LicenseAnalyzer {
	licensePatterns := map[string]*regexp.Regexp{
		// SPDX License identifiers - standard format
		"MIT":          regexp.MustCompile(`(?i)MIT\s+License|Permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge|SPDX-License-Identifier:\s*MIT`),
		"Apache-2.0":   regexp.MustCompile(`(?i)Apache\s+License,?\s+Version\s+2\.0|Licensed\s+under\s+the\s+Apache\s+License|SPDX-License-Identifier:\s*Apache-2\.0`),
		"GPL-3.0":      regexp.MustCompile(`(?i)GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+Version\s+3|GPL-3\.0|SPDX-License-Identifier:\s*GPL-3\.0`),
		"GPL-2.0":      regexp.MustCompile(`(?i)GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+Version\s+2|GPL-2\.0|SPDX-License-Identifier:\s*GPL-2\.0`),
		"BSD-3-Clause": regexp.MustCompile(`(?i)BSD\s+3-Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms.*3\s+clauses|SPDX-License-Identifier:\s*BSD-3-Clause`),
		"BSD-2-Clause": regexp.MustCompile(`(?i)BSD\s+2-Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms.*2\s+clauses|SPDX-License-Identifier:\s*BSD-2-Clause`),
		"ISC":          regexp.MustCompile(`(?i)ISC\s+License|Permission\s+to\s+use,\s+copy,\s+modify,\s+and/or\s+distribute|SPDX-License-Identifier:\s*ISC`),
		"LGPL-2.1":     regexp.MustCompile(`(?i)GNU\s+Lesser\s+General\s+Public\s+License.*Version\s+2\.1|LGPL-2\.1|SPDX-License-Identifier:\s*LGPL-2\.1`),
		"LGPL-3.0":     regexp.MustCompile(`(?i)GNU\s+Lesser\s+General\s+Public\s+License.*Version\s+3|LGPL-3\.0|SPDX-License-Identifier:\s*LGPL-3\.0`),
		"MPL-2.0":      regexp.MustCompile(`(?i)Mozilla\s+Public\s+License\s+Version\s+2\.0|MPL-2\.0|SPDX-License-Identifier:\s*MPL-2\.0`),
		"Unlicense":    regexp.MustCompile(`(?i)This\s+is\s+free\s+and\s+unencumbered\s+software\s+released\s+into\s+the\s+public\s+domain|SPDX-License-Identifier:\s*Unlicense`),
		"CC0-1.0":      regexp.MustCompile(`(?i)Creative\s+Commons\s+Zero|CC0\s+1\.0\s+Universal|SPDX-License-Identifier:\s*CC0-1\.0`),
		"Proprietary":  regexp.MustCompile(`(?i)All\s+rights\s+reserved|Proprietary|Internal\s+use\s+only|SPDX-License-Identifier:\s*LicenseRef-Proprietary`),

		// Additional SPDX-recognized licenses
		"GPL-3.0-or-later":                     regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*GPL-3\.0-or-later|GPL-3\.0\+`),
		"GPL-2.0-or-later":                     regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*GPL-2\.0-or-later|GPL-2\.0\+`),
		"LGPL-2.1-or-later":                    regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*LGPL-2\.1-or-later|LGPL-2\.1\+`),
		"LGPL-3.0-or-later":                    regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*LGPL-3\.0-or-later|LGPL-3\.0\+`),
		"GPL-3.0-only":                         regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*GPL-3\.0-only`),
		"GPL-2.0-only":                         regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*GPL-2\.0-only`),
		"LGPL-2.1-only":                        regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*LGPL-2\.1-only`),
		"LGPL-3.0-only":                        regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*LGPL-3\.0-only`),
		"BSD-2-Clause-Patent":                  regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*BSD-2-Clause-Patent`),
		"Apache-2.0 WITH LLVM-exception":       regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*Apache-2\.0\s+WITH\s+LLVM-exception`),
		"GPL-2.0 WITH Classpath-exception-2.0": regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*GPL-2\.0\s+WITH\s+Classpath-exception-2\.0`),
		"AGPL-3.0":                             regexp.MustCompile(`(?i)GNU\s+AFFERO\s+GENERAL\s+PUBLIC\s+LICENSE|AGPL-3\.0|SPDX-License-Identifier:\s*AGPL-3\.0`),
		"AGPL-3.0-only":                        regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*AGPL-3\.0-only`),
		"AGPL-3.0-or-later":                    regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*AGPL-3\.0-or-later`),
		"CC-BY-4.0":                            regexp.MustCompile(`(?i)Creative\s+Commons\s+Attribution\s+4\.0|SPDX-License-Identifier:\s*CC-BY-4\.0`),
		"CC-BY-SA-4.0":                         regexp.MustCompile(`(?i)Creative\s+Commons\s+Attribution-ShareAlike\s+4\.0|SPDX-License-Identifier:\s*CC-BY-SA-4\.0`),
		"CC-BY-NC-4.0":                         regexp.MustCompile(`(?i)Creative\s+Commons\s+Attribution-NonCommercial\s+4\.0|SPDX-License-Identifier:\s*CC-BY-NC-4\.0`),
		"CC-BY-NC-SA-4.0":                      regexp.MustCompile(`(?i)Creative\s+Commons\s+Attribution-NonCommercial-ShareAlike\s+4\.0|SPDX-License-Identifier:\s*CC-BY-NC-SA-4\.0`),
		"EPL-2.0":                              regexp.MustCompile(`(?i)Eclipse\s+Public\s+License.*Version\s+2\.0|SPDX-License-Identifier:\s*EPL-2\.0`),
		"EPL-1.0":                              regexp.MustCompile(`(?i)Eclipse\s+Public\s+License.*Version\s+1\.0|SPDX-License-Identifier:\s*EPL-1\.0`),
		"CDDL-1.0":                             regexp.MustCompile(`(?i)Common\s+Development\s+and\s+Distribution\s+License|SPDX-License-Identifier:\s*CDDL-1\.0`),
		"EUPL-1.2":                             regexp.MustCompile(`(?i)European\s+Union\s+Public\s+Licence|SPDX-License-Identifier:\s*EUPL-1\.2`),
		"0BSD":                                 regexp.MustCompile(`(?i)BSD\s+Zero\s+Clause|SPDX-License-Identifier:\s*0BSD`),
		"BSL-1.0":                              regexp.MustCompile(`(?i)Boost\s+Software\s+License|SPDX-License-Identifier:\s*BSL-1\.0`),
		"Zlib":                                 regexp.MustCompile(`(?i)zlib\s+License|SPDX-License-Identifier:\s*Zlib`),
		"Artistic-2.0":                         regexp.MustCompile(`(?i)Artistic\s+License\s+2\.0|SPDX-License-Identifier:\s*Artistic-2\.0`),
		"OFL-1.1":                              regexp.MustCompile(`(?i)SIL\s+Open\s+Font\s+License|SPDX-License-Identifier:\s*OFL-1\.1`),
		"WTFPL":                                regexp.MustCompile(`(?i)DO\s+WHAT\s+THE\s+FUCK\s+YOU\s+WANT\s+TO\s+PUBLIC\s+LICENSE|SPDX-License-Identifier:\s*WTFPL`),
		"PostgreSQL":                           regexp.MustCompile(`(?i)PostgreSQL\s+License|SPDX-License-Identifier:\s*PostgreSQL`),
		"MS-PL":                                regexp.MustCompile(`(?i)Microsoft\s+Public\s+License|SPDX-License-Identifier:\s*MS-PL`),
		"MS-RL":                                regexp.MustCompile(`(?i)Microsoft\s+Reciprocal\s+License|SPDX-License-Identifier:\s*MS-RL`),
		"NCSA":                                 regexp.MustCompile(`(?i)University\s+of\s+Illinois.*NCSA|SPDX-License-Identifier:\s*NCSA`),
		"AFL-3.0":                              regexp.MustCompile(`(?i)Academic\s+Free\s+License.*3\.0|SPDX-License-Identifier:\s*AFL-3\.0`),
		"OSL-3.0":                              regexp.MustCompile(`(?i)Open\s+Software\s+License.*3\.0|SPDX-License-Identifier:\s*OSL-3\.0`),
		"Ruby":                                 regexp.MustCompile(`(?i)Ruby\s+License|SPDX-License-Identifier:\s*Ruby`),
		"Python-2.0":                           regexp.MustCompile(`(?i)Python\s+Software\s+Foundation\s+License|SPDX-License-Identifier:\s*Python-2\.0`),
		"TCL":                                  regexp.MustCompile(`(?i)TCL/TK\s+License|SPDX-License-Identifier:\s*TCL`),
	}

	return &LicenseAnalyzer{
		licensePatterns: licensePatterns,
	}
}

func (l *LicenseAnalyzer) Name() string {
	return "license-analyzer"
}

func (l *LicenseAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeLicense,
		artifact.TypeReadme,
		artifact.TypeChangelog,
		artifact.TypeDocumentation,
		artifact.TypeManPage,
		artifact.TypeAPISpec,
		artifact.TypeSchemaFile,
	}
}

func (l *LicenseAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	// Check if source location exists
	if _, err := os.Stat(source.Location); os.IsNotExist(err) {
		return nil, err
	}

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())
		relPath, _ := filepath.Rel(source.Location, path)

		var artifactType artifact.Type
		var metadata map[string]string

		switch {
		// License files
		case l.isLicenseFile(fileName):
			artifactType = artifact.TypeLicense
			metadata = map[string]string{
				"document_type": "license",
			}
			// Try to detect license type from content
			if licenseType := l.detectLicenseType(path); licenseType != "" {
				metadata["license_type"] = licenseType
				metadata["spdx_id"] = l.getSPDXCompliantName(licenseType)
			}

		// README files
		case l.isReadmeFile(fileName):
			artifactType = artifact.TypeReadme
			metadata = map[string]string{
				"document_type": "readme",
				"format":        l.getDocumentFormat(fileName),
			}

		// Changelog files
		case l.isChangelogFile(fileName):
			artifactType = artifact.TypeChangelog
			metadata = map[string]string{
				"document_type": "changelog",
				"format":        l.getDocumentFormat(fileName),
			}

		// Documentation files
		case l.isDocumentationFile(fileName, path):
			artifactType = artifact.TypeDocumentation
			metadata = map[string]string{
				"document_type": "documentation",
				"format":        l.getDocumentFormat(fileName),
			}

		// Man pages
		case l.isManPage(fileName, path):
			artifactType = artifact.TypeManPage
			metadata = map[string]string{
				"document_type": "manual",
				"format":        "man",
			}

		// API specifications
		case l.isAPISpec(fileName):
			artifactType = artifact.TypeAPISpec
			metadata = map[string]string{
				"document_type": "api-specification",
				"format":        l.getAPISpecFormat(fileName),
			}

		// Schema files
		case l.isSchemaFile(fileName, path):
			artifactType = artifact.TypeSchemaFile
			metadata = map[string]string{
				"document_type": "schema",
				"format":        l.getSchemaFormat(fileName),
			}
		}

		if artifactType != "" {
			modTime := info.ModTime()
			artifact := artifact.Artifact{
				Name:        info.Name(),
				Type:        artifactType,
				Path:        relPath,
				Source:      source,
				Size:        info.Size(),
				Permissions: info.Mode().String(),
				ModTime:     &modTime,
				Metadata:    metadata,
			}
			artifacts = append(artifacts, artifact)
		}

		return nil
	})

	return artifacts, err
}

func (l *LicenseAnalyzer) isLicenseFile(fileName string) bool {
	licenseNames := []string{
		"license", "licence", "license.txt", "licence.txt",
		"license.md", "licence.md", "copying", "copying.txt",
		"license.rst", "licence.rst", "unlicense", "unlicense.txt",
	}

	for _, name := range licenseNames {
		if fileName == name {
			return true
		}
	}

	return false
}

func (l *LicenseAnalyzer) isReadmeFile(fileName string) bool {
	return strings.HasPrefix(fileName, "readme") ||
		fileName == "readme.txt" ||
		fileName == "readme.md" ||
		fileName == "readme.rst"
}

func (l *LicenseAnalyzer) isChangelogFile(fileName string) bool {
	changelogNames := []string{
		"changelog", "changelog.txt", "changelog.md", "changelog.rst",
		"changes", "changes.txt", "changes.md", "changes.rst",
		"history", "history.txt", "history.md", "history.rst",
		"news", "news.txt", "news.md", "news.rst",
		"releases", "releases.txt", "releases.md", "releases.rst",
	}

	for _, name := range changelogNames {
		if fileName == name {
			return true
		}
	}

	return false
}

func (l *LicenseAnalyzer) isDocumentationFile(fileName, path string) bool {
	// Documentation file extensions
	docExtensions := []string{".md", ".rst", ".txt", ".html", ".htm", ".tex", ".adoc", ".asciidoc"}

	for _, ext := range docExtensions {
		if strings.HasSuffix(fileName, ext) {
			// Check if in documentation directories - normalize path separators
			pathLower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
			if strings.Contains(pathLower, "/doc/") ||
				strings.Contains(pathLower, "/docs/") ||
				strings.Contains(pathLower, "/documentation/") ||
				strings.Contains(pathLower, "/manual/") ||
				strings.Contains(pathLower, "/help/") {
				return true
			}
		}
	}

	return false
}

func (l *LicenseAnalyzer) isManPage(fileName, path string) bool {
	// Man page files are typically in man/ directories with numeric extensions - normalize path separators
	pathLower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.Contains(pathLower, "/man/") {
		// Man pages have extensions like .1, .2, .3, etc.
		if matched, _ := regexp.MatchString(`\.[1-9]$`, fileName); matched {
			return true
		}
		if matched, _ := regexp.MatchString(`\.[1-9]\.gz$`, fileName); matched {
			return true
		}
	}
	return false
}

func (l *LicenseAnalyzer) isAPISpec(fileName string) bool {
	apiSpecFiles := []string{
		"swagger.json", "swagger.yaml", "swagger.yml",
		"openapi.json", "openapi.yaml", "openapi.yml",
		"api.json", "api.yaml", "api.yml",
		"spec.json", "spec.yaml", "spec.yml",
	}

	for _, name := range apiSpecFiles {
		if fileName == name {
			return true
		}
	}

	// Check for OpenAPI/Swagger patterns in filename
	return strings.Contains(fileName, "openapi") ||
		strings.Contains(fileName, "swagger") ||
		(strings.Contains(fileName, "api") && (strings.HasSuffix(fileName, ".json") ||
			strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml")))
}

func (l *LicenseAnalyzer) isSchemaFile(fileName, path string) bool {
	schemaFiles := []string{
		"schema.json", "schema.yaml", "schema.yml",
		"schema.xsd", "schema.xml",
	}

	for _, name := range schemaFiles {
		if fileName == name {
			return true
		}
	}

	// GraphQL schema files
	if strings.HasSuffix(fileName, ".graphql") || strings.HasSuffix(fileName, ".gql") {
		return true
	}

	// JSON Schema files
	if strings.Contains(fileName, "schema") && strings.HasSuffix(fileName, ".json") {
		return true
	}

	// Check if file is in schema directories - normalize path separators
	pathLower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.Contains(pathLower, "/schema/") || strings.Contains(pathLower, "/schemas/") {
		// JSON, YAML, or XML files in schema directories
		if strings.HasSuffix(fileName, ".json") ||
			strings.HasSuffix(fileName, ".yaml") ||
			strings.HasSuffix(fileName, ".yml") ||
			strings.HasSuffix(fileName, ".xsd") ||
			strings.HasSuffix(fileName, ".xml") {
			return true
		}
	}

	return false
}

func (l *LicenseAnalyzer) detectLicenseType(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	contentStr := string(content)

	// First try to extract SPDX license identifier directly
	if spdxLicense := l.extractSPDXLicense(contentStr); spdxLicense != "" {
		return spdxLicense
	}

	// Fall back to pattern matching
	for licenseType, pattern := range l.licensePatterns {
		if pattern.MatchString(contentStr) {
			return licenseType
		}
	}

	return "unknown"
}

// extractSPDXLicense extracts SPDX license identifier from file content
func (l *LicenseAnalyzer) extractSPDXLicense(content string) string {
	// SPDX license identifier pattern - more specific to capture just the license ID
	spdxPattern := regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*([A-Za-z0-9\.\-\+]+(?:\s+WITH\s+[A-Za-z0-9\.\-\+]+)?)`)

	matches := spdxPattern.FindStringSubmatch(content)
	if len(matches) > 1 {
		// Clean up the license identifier
		license := strings.TrimSpace(matches[1])
		return license
	}

	return ""
}

// getSPDXCompliantName returns the SPDX compliant name for a license
func (l *LicenseAnalyzer) getSPDXCompliantName(detectedLicense string) string {
	// Map common license names to SPDX identifiers
	spdxMap := map[string]string{
		"MIT":          "MIT",
		"Apache-2.0":   "Apache-2.0",
		"GPL-3.0":      "GPL-3.0-only",
		"GPL-2.0":      "GPL-2.0-only",
		"BSD-3-Clause": "BSD-3-Clause",
		"BSD-2-Clause": "BSD-2-Clause",
		"ISC":          "ISC",
		"LGPL-2.1":     "LGPL-2.1-only",
		"LGPL-3.0":     "LGPL-3.0-only",
		"MPL-2.0":      "MPL-2.0",
		"Unlicense":    "Unlicense",
		"CC0-1.0":      "CC0-1.0",
		"AGPL-3.0":     "AGPL-3.0-only",
		"EPL-2.0":      "EPL-2.0",
		"EPL-1.0":      "EPL-1.0",
		"CDDL-1.0":     "CDDL-1.0",
		"EUPL-1.2":     "EUPL-1.2",
		"0BSD":         "0BSD",
		"BSL-1.0":      "BSL-1.0",
		"Zlib":         "Zlib",
		"Artistic-2.0": "Artistic-2.0",
		"OFL-1.1":      "OFL-1.1",
		"WTFPL":        "WTFPL",
		"PostgreSQL":   "PostgreSQL",
		"MS-PL":        "MS-PL",
		"MS-RL":        "MS-RL",
		"NCSA":         "NCSA",
		"AFL-3.0":      "AFL-3.0",
		"OSL-3.0":      "OSL-3.0",
		"Ruby":         "Ruby",
		"Python-2.0":   "Python-2.0",
		"TCL":          "TCL",
		"Proprietary":  "LicenseRef-Proprietary",
	}

	if spdxName, exists := spdxMap[detectedLicense]; exists {
		return spdxName
	}

	return detectedLicense
}

// isValidSPDXLicense checks if a license identifier is a valid SPDX license
func (l *LicenseAnalyzer) isValidSPDXLicense(license string) bool {
	// Common SPDX license identifiers
	validSPDXLicenses := map[string]bool{
		"MIT": true, "Apache-2.0": true, "GPL-2.0-only": true, "GPL-2.0-or-later": true,
		"GPL-3.0-only": true, "GPL-3.0-or-later": true, "LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
		"LGPL-3.0-only": true, "LGPL-3.0-or-later": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
		"ISC": true, "MPL-2.0": true, "Unlicense": true, "CC0-1.0": true, "AGPL-3.0-only": true,
		"AGPL-3.0-or-later": true, "EPL-1.0": true, "EPL-2.0": true, "CDDL-1.0": true,
		"EUPL-1.2": true, "0BSD": true, "BSL-1.0": true, "Zlib": true, "Artistic-2.0": true,
		"OFL-1.1": true, "WTFPL": true, "PostgreSQL": true, "MS-PL": true, "MS-RL": true,
		"NCSA": true, "AFL-3.0": true, "OSL-3.0": true, "Ruby": true, "Python-2.0": true,
		"TCL": true, "CC-BY-4.0": true, "CC-BY-SA-4.0": true, "CC-BY-NC-4.0": true,
		"CC-BY-NC-SA-4.0": true, "BSD-2-Clause-Patent": true,
	}

	// Check if it's a standard SPDX license
	if validSPDXLicenses[license] {
		return true
	}

	// Check if it's a license exception (WITH clause)
	if strings.Contains(license, " WITH ") {
		return true
	}

	// Check if it's a LicenseRef (custom license reference)
	if strings.HasPrefix(license, "LicenseRef-") {
		return true
	}

	return false
}

// scanForSPDXInSourceFiles scans source files for SPDX license identifiers
// This is useful for projects that include SPDX headers in source files
func (l *LicenseAnalyzer) scanForSPDXInSourceFiles(sourcePath string) (map[string]int, error) {
	licenseFrequency := make(map[string]int)
	sourceExtensions := []string{".go", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".rs", ".php", ".rb", ".sh"}

	err := filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Check if it's a source file
		isSourceFile := false
		for _, ext := range sourceExtensions {
			if strings.HasSuffix(strings.ToLower(info.Name()), ext) {
				isSourceFile = true
				break
			}
		}

		if !isSourceFile {
			return nil
		}

		// Read first 50 lines to check for SPDX headers
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		searchLines := len(lines)
		if searchLines > 50 {
			searchLines = 50 // Only check first 50 lines
		}

		headerContent := strings.Join(lines[:searchLines], "\n")
		if spdxLicense := l.extractSPDXLicense(headerContent); spdxLicense != "" {
			licenseFrequency[spdxLicense]++
		}

		return nil
	})

	return licenseFrequency, err
}

func (l *LicenseAnalyzer) getDocumentFormat(fileName string) string {
	switch {
	case strings.HasSuffix(fileName, ".md"):
		return "markdown"
	case strings.HasSuffix(fileName, ".rst"):
		return "restructuredtext"
	case strings.HasSuffix(fileName, ".html") || strings.HasSuffix(fileName, ".htm"):
		return "html"
	case strings.HasSuffix(fileName, ".tex"):
		return "latex"
	case strings.HasSuffix(fileName, ".adoc") || strings.HasSuffix(fileName, ".asciidoc"):
		return "asciidoc"
	case strings.HasSuffix(fileName, ".txt"):
		return "plain-text"
	default:
		return "unknown"
	}
}

func (l *LicenseAnalyzer) getAPISpecFormat(fileName string) string {
	switch {
	case strings.HasSuffix(fileName, ".json"):
		return "json"
	case strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml"):
		return "yaml"
	default:
		return "unknown"
	}
}

func (l *LicenseAnalyzer) getSchemaFormat(fileName string) string {
	switch {
	case strings.HasSuffix(fileName, ".json"):
		return "json-schema"
	case strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml"):
		return "yaml-schema"
	case strings.HasSuffix(fileName, ".xsd"):
		return "xml-schema"
	case strings.HasSuffix(fileName, ".graphql") || strings.HasSuffix(fileName, ".gql"):
		return "graphql"
	default:
		return "unknown"
	}
}
