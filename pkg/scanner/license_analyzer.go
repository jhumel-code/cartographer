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
		"MIT":          regexp.MustCompile(`(?i)MIT\s+License|Permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge`),
		"Apache-2.0":   regexp.MustCompile(`(?i)Apache\s+License,?\s+Version\s+2\.0|Licensed\s+under\s+the\s+Apache\s+License`),
		"GPL-3.0":      regexp.MustCompile(`(?i)GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+Version\s+3|GPL-3\.0`),
		"GPL-2.0":      regexp.MustCompile(`(?i)GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+Version\s+2|GPL-2\.0`),
		"BSD-3-Clause": regexp.MustCompile(`(?i)BSD\s+3-Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms.*3\s+clauses`),
		"BSD-2-Clause": regexp.MustCompile(`(?i)BSD\s+2-Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms.*2\s+clauses`),
		"ISC":          regexp.MustCompile(`(?i)ISC\s+License|Permission\s+to\s+use,\s+copy,\s+modify,\s+and/or\s+distribute`),
		"LGPL":         regexp.MustCompile(`(?i)GNU\s+Lesser\s+General\s+Public\s+License|LGPL`),
		"MPL-2.0":      regexp.MustCompile(`(?i)Mozilla\s+Public\s+License\s+Version\s+2\.0|MPL-2\.0`),
		"Unlicense":    regexp.MustCompile(`(?i)This\s+is\s+free\s+and\s+unencumbered\s+software\s+released\s+into\s+the\s+public\s+domain`),
		"CC0":          regexp.MustCompile(`(?i)Creative\s+Commons\s+Zero|CC0\s+1\.0\s+Universal`),
		"Proprietary":  regexp.MustCompile(`(?i)All\s+rights\s+reserved|Proprietary|Internal\s+use\s+only`),
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
		case l.isSchemaFile(fileName):
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
			// Check if in documentation directories
			pathLower := strings.ToLower(path)
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
	// Man page files are typically in man/ directories with numeric extensions
	pathLower := strings.ToLower(path)
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

func (l *LicenseAnalyzer) isSchemaFile(fileName string) bool {
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

	return false
}

func (l *LicenseAnalyzer) detectLicenseType(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	contentStr := string(content)

	for licenseType, pattern := range l.licensePatterns {
		if pattern.MatchString(contentStr) {
			return licenseType
		}
	}

	return "unknown"
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
