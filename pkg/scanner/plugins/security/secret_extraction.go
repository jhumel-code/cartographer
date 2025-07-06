package security

import (
	"context"
	"regexp"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// SecretExtractionPlugin detects and extracts secret patterns from artifacts
type SecretExtractionPlugin struct {
	secretPatterns map[string]*regexp.Regexp
}

// NewSecretExtractionPlugin creates a new secret extraction plugin
func NewSecretExtractionPlugin() *SecretExtractionPlugin {
	plugin := &SecretExtractionPlugin{
		secretPatterns: make(map[string]*regexp.Regexp),
	}

	plugin.initializeSecretPatterns()
	return plugin
}

// Name returns the plugin name
func (p *SecretExtractionPlugin) Name() string {
	return "secret-extraction-plugin"
}

// Priority returns the execution priority (lower numbers execute first)
func (p *SecretExtractionPlugin) Priority() int {
	return 30 // Run after vendor mapping and license mapping
}

// SupportedTypes returns the types this plugin can process for secrets
func (p *SecretExtractionPlugin) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeConfigFile,
		artifact.TypeEnvironmentFile,
		artifact.TypeShellScript,
		artifact.TypePythonScript,
		artifact.TypeDockerfile,
		artifact.TypeKubernetesManifest,
		artifact.TypeSecret,
		artifact.TypeAPIKey,
		artifact.TypeToken,
		artifact.TypePassword,
	}
}

// Process scans artifacts for potential secrets and adds metadata
func (p *SecretExtractionPlugin) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	enhancedArtifacts := make([]artifact.Artifact, 0, len(artifacts))

	for _, art := range artifacts {
		enhanced := art

		// Scan for secrets if the artifact has content
		if content, exists := art.Metadata["content"]; exists {
			secrets := p.extractSecrets(content)
			if len(secrets) > 0 {
				enhanced = p.addSecretMetadata(enhanced, secrets)
			}
		}

		// Also scan file path for potential secret patterns
		pathSecrets := p.extractSecretsFromPath(art.Path)
		if len(pathSecrets) > 0 {
			enhanced = p.addSecretMetadata(enhanced, pathSecrets)
		}

		enhancedArtifacts = append(enhancedArtifacts, enhanced)
	}

	return enhancedArtifacts, nil
}

// extractSecrets finds potential secrets in content
func (p *SecretExtractionPlugin) extractSecrets(content string) []SecretMatch {
	var secrets []SecretMatch

	for secretType, pattern := range p.secretPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			secrets = append(secrets, SecretMatch{
				Type:    secretType,
				Pattern: match,
				Masked:  p.maskSecret(match),
			})
		}
	}

	return secrets
}

// extractSecretsFromPath finds potential secrets in file paths
func (p *SecretExtractionPlugin) extractSecretsFromPath(path string) []SecretMatch {
	var secrets []SecretMatch

	// Common secret file patterns
	secretFiles := []string{
		".env", ".environment", "secrets.yaml", "secrets.yml",
		"credentials.json", "auth.json", "private.key", ".pem",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	}

	lowerPath := strings.ToLower(path)
	for _, secretFile := range secretFiles {
		if strings.Contains(lowerPath, secretFile) {
			secrets = append(secrets, SecretMatch{
				Type:    "potential-secret-file",
				Pattern: secretFile,
				Masked:  secretFile,
			})
		}
	}

	return secrets
}

// addSecretMetadata adds secret information to artifact metadata
func (p *SecretExtractionPlugin) addSecretMetadata(art artifact.Artifact, secrets []SecretMatch) artifact.Artifact {
	if art.Metadata == nil {
		art.Metadata = make(map[string]string)
	}

	// Add secret detection flag
	art.Metadata["has_secrets"] = "true"
	art.Metadata["secret_count"] = string(rune(len(secrets)))

	// Add secret types
	var secretTypes []string
	for _, secret := range secrets {
		secretTypes = append(secretTypes, secret.Type)
	}
	art.Metadata["secret_types"] = strings.Join(secretTypes, ",")

	return art
}

// maskSecret masks sensitive parts of the secret
func (p *SecretExtractionPlugin) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}

	// Show first 4 and last 4 characters
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// SecretMatch represents a found secret pattern
type SecretMatch struct {
	Type    string
	Pattern string
	Masked  string
}

// initializeSecretPatterns sets up regex patterns for common secrets
func (p *SecretExtractionPlugin) initializeSecretPatterns() {
	patterns := map[string]string{
		"aws-access-key":     `AKIA[0-9A-Z]{16}`,
		"aws-secret-key":     `[0-9a-zA-Z/+]{40}`,
		"github-token":       `ghp_[0-9a-zA-Z]{36}`,
		"gitlab-token":       `glpat-[0-9a-zA-Z\-_]{20}`,
		"slack-token":        `xox[baprs]-[0-9a-zA-Z\-]{10,72}`,
		"google-api-key":     `AIza[0-9a-zA-Z\-_]{35}`,
		"firebase-key":       `AAAA[0-9a-zA-Z\-_:]{134}`,
		"private-key-header": `-----BEGIN [A-Z ]+PRIVATE KEY-----`,
		"jwt-token":          `eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`,
		"password-in-url":    `[a-zA-Z][a-zA-Z0-9+\.-]*://[^:]+:[^@]+@`,
		"generic-secret":     `(?i)(secret|password|pwd|token|key)\s*[=:]\s*['""]?[a-zA-Z0-9+/=\-_!@#$%^&*()]{8,}['""]?`,
	}

	for name, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			p.secretPatterns[name] = compiled
		}
	}
}
