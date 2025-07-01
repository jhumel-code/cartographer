package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// SecurityAnalyzer scans for security-related artifacts like secrets, keys, and certificates
type SecurityAnalyzer struct {
	secretPatterns []*regexp.Regexp
	keyPatterns    []*regexp.Regexp
}

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer() *SecurityAnalyzer {
	secretPatterns := []*regexp.Regexp{
		// API Keys and Tokens
		regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`),
		regexp.MustCompile(`(?i)secret[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`),
		regexp.MustCompile(`(?i)access[_-]?token\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`),
		regexp.MustCompile(`(?i)auth[_-]?token\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`),

		// AWS
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"][a-zA-Z0-9/+=]{40}['"]`),

		// GitHub
		regexp.MustCompile(`(?i)github[_-]?token\s*[:=]\s*['"]ghp_[a-zA-Z0-9]{36}['"]`),
		regexp.MustCompile(`(?i)github[_-]?pat\s*[:=]\s*['"]ghp_[a-zA-Z0-9]{36}['"]`),

		// Generic passwords
		regexp.MustCompile(`(?i)password\s*[:=]\s*['"][^'"]{8,}['"]`),
		regexp.MustCompile(`(?i)passwd\s*[:=]\s*['"][^'"]{8,}['"]`),
		regexp.MustCompile(`(?i)pwd\s*[:=]\s*['"][^'"]{8,}['"]`),

		// Database connection strings
		regexp.MustCompile(`(?i)postgres://[^'"]+`),
		regexp.MustCompile(`(?i)mysql://[^'"]+`),
		regexp.MustCompile(`(?i)mongodb://[^'"]+`),

		// JWT Tokens
		regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
	}

	keyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`),
		regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----`),
		regexp.MustCompile(`-----BEGIN\s+CERTIFICATE-----`),
		regexp.MustCompile(`-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----`),
		regexp.MustCompile(`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----`),
		regexp.MustCompile(`-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`),
		regexp.MustCompile(`-----BEGIN\s+PGP\s+PUBLIC\s+KEY\s+BLOCK-----`),
	}

	return &SecurityAnalyzer{
		secretPatterns: secretPatterns,
		keyPatterns:    keyPatterns,
	}
}

func (s *SecurityAnalyzer) Name() string {
	return "security-analyzer"
}

func (s *SecurityAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeCertificate,
		artifact.TypePrivateKey,
		artifact.TypePublicKey,
		artifact.TypeAPIKey,
		artifact.TypePassword,
		artifact.TypeToken,
		artifact.TypeSecret,
		artifact.TypeKeystore,
		artifact.TypeTruststore,
	}
}

func (s *SecurityAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())
		relPath, _ := filepath.Rel(source.Location, path)

		// Check for key files by extension
		switch {
		case strings.HasSuffix(fileName, ".pem"):
			artifacts = append(artifacts, s.createCertificateArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".crt"), strings.HasSuffix(fileName, ".cer"):
			artifacts = append(artifacts, s.createCertificateArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".key"):
			artifacts = append(artifacts, s.createPrivateKeyArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".pub"):
			artifacts = append(artifacts, s.createPublicKeyArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".p12"), strings.HasSuffix(fileName, ".pfx"):
			artifacts = append(artifacts, s.createKeystoreArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".jks"), strings.HasSuffix(fileName, ".keystore"):
			artifacts = append(artifacts, s.createKeystoreArtifact(path, relPath, info, source))
		case strings.HasSuffix(fileName, ".truststore"):
			artifacts = append(artifacts, s.createTruststoreArtifact(path, relPath, info, source))
		}

		// Scan file content for secrets (only for text files under 1MB)
		if info.Size() < 1024*1024 && s.isTextFile(fileName) {
			secretArtifacts := s.scanFileForSecrets(path, relPath, info, source)
			artifacts = append(artifacts, secretArtifacts...)
		}

		return nil
	})

	return artifacts, err
}

func (s *SecurityAnalyzer) createCertificateArtifact(path, relPath string, info os.FileInfo, source artifact.Source) artifact.Artifact {
	modTime := info.ModTime()
	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeCertificate,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": "certificate",
			"extension": filepath.Ext(info.Name()),
		},
	}
}

func (s *SecurityAnalyzer) createPrivateKeyArtifact(path, relPath string, info os.FileInfo, source artifact.Source) artifact.Artifact {
	modTime := info.ModTime()
	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypePrivateKey,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": "private-key",
			"extension": filepath.Ext(info.Name()),
		},
	}
}

func (s *SecurityAnalyzer) createPublicKeyArtifact(path, relPath string, info os.FileInfo, source artifact.Source) artifact.Artifact {
	modTime := info.ModTime()
	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypePublicKey,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": "public-key",
			"extension": filepath.Ext(info.Name()),
		},
	}
}

func (s *SecurityAnalyzer) createKeystoreArtifact(path, relPath string, info os.FileInfo, source artifact.Source) artifact.Artifact {
	modTime := info.ModTime()
	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeKeystore,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": "keystore",
			"extension": filepath.Ext(info.Name()),
		},
	}
}

func (s *SecurityAnalyzer) createTruststoreArtifact(path, relPath string, info os.FileInfo, source artifact.Source) artifact.Artifact {
	modTime := info.ModTime()
	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeTruststore,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata: map[string]string{
			"file_type": "truststore",
			"extension": filepath.Ext(info.Name()),
		},
	}
}

func (s *SecurityAnalyzer) scanFileForSecrets(path, relPath string, info os.FileInfo, source artifact.Source) []artifact.Artifact {
	var artifacts []artifact.Artifact

	content, err := os.ReadFile(path)
	if err != nil {
		return artifacts
	}

	fileContent := string(content)
	modTime := info.ModTime()

	// Check for secrets
	for _, pattern := range s.secretPatterns {
		matches := pattern.FindAllString(fileContent, -1)
		for _, match := range matches {
			secretType := s.classifySecret(match)
			artifact := artifact.Artifact{
				Name:    "secret-" + secretType,
				Type:    artifact.TypeSecret,
				Path:    relPath,
				Source:  source,
				ModTime: &modTime,
				Metadata: map[string]string{
					"secret_type":  secretType,
					"found_in":     info.Name(),
					"pattern_type": "regex",
				},
			}
			artifacts = append(artifacts, artifact)
		}
	}

	// Check for key blocks
	for _, pattern := range s.keyPatterns {
		if pattern.MatchString(fileContent) {
			keyType := s.classifyKeyBlock(pattern.String())
			artifact := artifact.Artifact{
				Name:    "key-" + keyType,
				Type:    s.getKeyArtifactType(keyType),
				Path:    relPath,
				Source:  source,
				ModTime: &modTime,
				Metadata: map[string]string{
					"key_type":     keyType,
					"found_in":     info.Name(),
					"pattern_type": "pem-block",
				},
			}
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts
}

func (s *SecurityAnalyzer) classifySecret(match string) string {
	lower := strings.ToLower(match)
	switch {
	case strings.Contains(lower, "api"):
		return "api-key"
	case strings.Contains(lower, "token"):
		return "token"
	case strings.Contains(lower, "password") || strings.Contains(lower, "passwd"):
		return "password"
	case strings.Contains(lower, "secret"):
		return "secret-key"
	case strings.Contains(lower, "aws"):
		return "aws-credential"
	case strings.Contains(lower, "github"):
		return "github-token"
	case strings.Contains(lower, "jwt") || strings.HasPrefix(match, "eyJ"):
		return "jwt-token"
	default:
		return "unknown"
	}
}

func (s *SecurityAnalyzer) classifyKeyBlock(pattern string) string {
	switch {
	case strings.Contains(pattern, "PRIVATE"):
		return "private-key"
	case strings.Contains(pattern, "PUBLIC"):
		return "public-key"
	case strings.Contains(pattern, "CERTIFICATE"):
		return "certificate"
	case strings.Contains(pattern, "PGP"):
		return "pgp-key"
	default:
		return "unknown-key"
	}
}

func (s *SecurityAnalyzer) getKeyArtifactType(keyType string) artifact.Type {
	switch keyType {
	case "private-key":
		return artifact.TypePrivateKey
	case "public-key":
		return artifact.TypePublicKey
	case "certificate":
		return artifact.TypeCertificate
	default:
		return artifact.TypeSecret
	}
}

func (s *SecurityAnalyzer) isTextFile(fileName string) bool {
	textExtensions := []string{
		".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".conf", ".config",
		".env", ".ini", ".properties", ".sh", ".py", ".js", ".ts", ".go",
		".java", ".rb", ".php", ".sql", ".html", ".css", ".dockerfile",
	}

	for _, ext := range textExtensions {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}

	// Files without extensions might be text
	return !strings.Contains(fileName, ".")
}
