package security

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
	"github.com/ianjhumelbautista/cartographer/pkg/scanner/core"
)

// CertificateScanner scans for SSL/TLS certificates
type CertificateScanner struct {
	*core.BaseScanner
}

// NewCertificateScanner creates a new certificate scanner
func NewCertificateScanner() *CertificateScanner {
	patterns := []string{
		"*.pem",
		"*.crt",
		"*.cer",
		"*.p12",
		"*.pfx",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeCertificate,
	}

	return &CertificateScanner{
		BaseScanner: core.NewBaseScanner("certificate-scanner", supportedTypes, patterns),
	}
}

// Scan scans for certificates in the source
func (c *CertificateScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return c.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !c.MatchesFile(filename, path) {
			return nil, nil
		}

		return c.parseCertificateFile(path, source, info)
	})
}

// parseCertificateFile parses a certificate file and extracts metadata
func (c *CertificateScanner) parseCertificateFile(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		// Create basic artifact even if parsing fails
		return []artifact.Artifact{c.createBasicCertificateArtifact(path, source, info)}, nil
	}

	parser := &certificateParser{
		path:   path,
		source: source,
		info:   info,
	}

	return parser.parse(content)
}

// certificateParser handles certificate file parsing
type certificateParser struct {
	path     string
	source   artifact.Source
	info     os.FileInfo
	metadata map[string]string
}

// parse processes the certificate content
func (p *certificateParser) parse(content []byte) ([]artifact.Artifact, error) {
	p.initializeMetadata()

	if block, _ := pem.Decode(content); block != nil {
		p.parsePEMBlock(block)
	} else {
		p.metadata["format"] = "binary"
	}

	return []artifact.Artifact{p.createArtifact()}, nil
}

// initializeMetadata sets up basic metadata
func (p *certificateParser) initializeMetadata() {
	p.metadata = map[string]string{
		"security_type": "certificate",
		"file_type":     strings.ToLower(filepath.Ext(p.path)),
	}
}

// parsePEMBlock parses a PEM block and extracts certificate details
func (p *certificateParser) parsePEMBlock(block *pem.Block) {
	p.metadata["format"] = "pem"
	p.metadata["pem_type"] = block.Type

	if block.Type == "CERTIFICATE" {
		p.parseCertificateDetails(block.Bytes)
	}
}

// parseCertificateDetails extracts X.509 certificate details
func (p *certificateParser) parseCertificateDetails(certBytes []byte) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return
	}

	p.metadata["subject"] = cert.Subject.String()
	p.metadata["issuer"] = cert.Issuer.String()
	p.metadata["serial_number"] = cert.SerialNumber.String()
	p.metadata["not_before"] = cert.NotBefore.Format(time.RFC3339)
	p.metadata["not_after"] = cert.NotAfter.Format(time.RFC3339)

	if len(cert.DNSNames) > 0 {
		p.metadata["dns_names"] = strings.Join(cert.DNSNames, ", ")
	}

	p.metadata["expired"] = p.getExpirationStatus(cert)
}

// getExpirationStatus checks if certificate is expired
func (p *certificateParser) getExpirationStatus(cert *x509.Certificate) string {
	if time.Now().After(cert.NotAfter) {
		return "true"
	}
	return "false"
}

// createArtifact creates the final artifact
func (p *certificateParser) createArtifact() artifact.Artifact {
	modTime := p.info.ModTime()
	relPath, _ := filepath.Rel(p.source.Location, p.path)

	return artifact.Artifact{
		Name:        p.info.Name(),
		Type:        artifact.TypeCertificate,
		Path:        relPath,
		Source:      p.source,
		Size:        p.info.Size(),
		Permissions: p.info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    p.metadata,
	}
}

// createBasicCertificateArtifact creates a basic certificate artifact when parsing fails
func (c *CertificateScanner) createBasicCertificateArtifact(path string, source artifact.Source, info os.FileInfo) artifact.Artifact {
	metadata := map[string]string{
		"security_type": "certificate",
		"file_type":     strings.ToLower(filepath.Ext(path)),
		"parse_error":   "true",
	}

	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeCertificate,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}
}

// KeyScanner scans for private and public keys
type KeyScanner struct {
	*core.BaseScanner
}

// NewKeyScanner creates a new key scanner
func NewKeyScanner() *KeyScanner {
	patterns := []string{
		"*.key",
		"*.pub",
		"id_rsa",
		"id_dsa",
		"id_ecdsa",
		"id_ed25519",
	}

	supportedTypes := []artifact.Type{
		artifact.TypePrivateKey,
		artifact.TypePublicKey,
	}

	return &KeyScanner{
		BaseScanner: core.NewBaseScanner("key-scanner", supportedTypes, patterns),
	}
}

// Scan scans for cryptographic keys in the source
func (k *KeyScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return k.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !k.MatchesFile(filename, path) {
			return nil, nil
		}

		return k.parseKeyFile(path, source, info)
	})
}

// parseKeyFile parses a key file and determines its type
func (k *KeyScanner) parseKeyFile(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return []artifact.Artifact{k.createBasicKeyArtifact(path, source, info, "unknown")}, nil
	}

	parser := &keyParser{
		path:   path,
		source: source,
		info:   info,
	}

	return parser.parse(content)
}

// keyParser handles key file parsing
type keyParser struct {
	path     string
	source   artifact.Source
	info     os.FileInfo
	metadata map[string]string
}

// parse processes the key content
func (p *keyParser) parse(content []byte) ([]artifact.Artifact, error) {
	p.initializeMetadata()

	keyType := p.determineKeyType(content)
	p.metadata["key_type"] = keyType

	if block, _ := pem.Decode(content); block != nil {
		p.parsePEMKey(block)
	} else {
		p.metadata["format"] = "binary"
	}

	artifactType := p.getArtifactType(keyType)
	return []artifact.Artifact{p.createArtifact(artifactType)}, nil
}

// initializeMetadata sets up basic metadata
func (p *keyParser) initializeMetadata() {
	p.metadata = map[string]string{
		"security_type": "key",
		"file_type":     strings.ToLower(filepath.Ext(p.path)),
	}
}

// determineKeyType determines the type of key based on filename and content
func (p *keyParser) determineKeyType(content []byte) string {
	filename := strings.ToLower(p.info.Name())
	contentStr := string(content)

	// Check by filename patterns
	if strings.Contains(filename, ".pub") || strings.HasSuffix(filename, ".public") {
		return "public"
	}
	if strings.Contains(filename, "private") || strings.Contains(filename, ".key") {
		return "private"
	}

	// Check by PEM headers
	if strings.Contains(contentStr, "BEGIN PUBLIC KEY") ||
		strings.Contains(contentStr, "BEGIN RSA PUBLIC KEY") ||
		strings.Contains(contentStr, "BEGIN DSA PUBLIC KEY") ||
		strings.Contains(contentStr, "BEGIN EC PUBLIC KEY") {
		return "public"
	}

	if strings.Contains(contentStr, "BEGIN PRIVATE KEY") ||
		strings.Contains(contentStr, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(contentStr, "BEGIN DSA PRIVATE KEY") ||
		strings.Contains(contentStr, "BEGIN EC PRIVATE KEY") ||
		strings.Contains(contentStr, "BEGIN OPENSSH PRIVATE KEY") {
		return "private"
	}

	// Default based on common SSH key names
	switch filename {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return "private"
	case "id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub":
		return "public"
	}

	return "unknown"
}

// parsePEMKey extracts details from PEM-encoded keys
func (p *keyParser) parsePEMKey(block *pem.Block) {
	p.metadata["format"] = "pem"
	p.metadata["pem_type"] = block.Type

	// Determine algorithm from PEM type
	switch block.Type {
	case "RSA PRIVATE KEY", "RSA PUBLIC KEY":
		p.metadata["algorithm"] = "RSA"
	case "DSA PRIVATE KEY", "DSA PUBLIC KEY":
		p.metadata["algorithm"] = "DSA"
	case "EC PRIVATE KEY", "EC PUBLIC KEY":
		p.metadata["algorithm"] = "ECDSA"
	case "OPENSSH PRIVATE KEY":
		p.metadata["algorithm"] = "OpenSSH"
	default:
		p.metadata["algorithm"] = "unknown"
	}
}

// getArtifactType maps key type to artifact type
func (p *keyParser) getArtifactType(keyType string) artifact.Type {
	if keyType == "public" {
		return artifact.TypePublicKey
	}
	return artifact.TypePrivateKey
}

// createArtifact creates the final artifact
func (p *keyParser) createArtifact(artifactType artifact.Type) artifact.Artifact {
	modTime := p.info.ModTime()
	relPath, _ := filepath.Rel(p.source.Location, p.path)

	return artifact.Artifact{
		Name:        p.info.Name(),
		Type:        artifactType,
		Path:        relPath,
		Source:      p.source,
		Size:        p.info.Size(),
		Permissions: p.info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    p.metadata,
	}
}

// createBasicKeyArtifact creates a basic key artifact when parsing fails
func (k *KeyScanner) createBasicKeyArtifact(path string, source artifact.Source, info os.FileInfo, keyType string) artifact.Artifact {
	metadata := map[string]string{
		"security_type": "key",
		"key_type":      keyType,
		"file_type":     strings.ToLower(filepath.Ext(path)),
		"parse_error":   "true",
	}

	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	artifactType := artifact.TypePrivateKey
	if keyType == "public" {
		artifactType = artifact.TypePublicKey
	}

	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifactType,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}
}

// LicenseScanner scans for license files
type LicenseScanner struct {
	*core.BaseScanner
}

// NewLicenseScanner creates a new license scanner
func NewLicenseScanner() *LicenseScanner {
	patterns := []string{
		"LICENSE",
		"LICENSE.*",
		"COPYING",
		"COPYRIGHT",
		"NOTICE",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeLicense,
	}

	return &LicenseScanner{
		BaseScanner: core.NewBaseScanner("license-scanner", supportedTypes, patterns),
	}
}

// Scan scans for license files in the source
func (l *LicenseScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return l.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := info.Name()

		if !l.MatchesFile(filename, path) {
			return nil, nil
		}

		return l.parseLicenseFile(path, source, info)
	})
}

// parseLicenseFile parses a license file and extracts license information
func (l *LicenseScanner) parseLicenseFile(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return []artifact.Artifact{l.createBasicLicenseArtifact(path, source, info)}, nil
	}

	parser := &licenseParser{
		path:   path,
		source: source,
		info:   info,
	}

	return parser.parse(content)
}

// licenseParser handles license file parsing
type licenseParser struct {
	path     string
	source   artifact.Source
	info     os.FileInfo
	metadata map[string]string
}

// parse processes the license content
func (p *licenseParser) parse(content []byte) ([]artifact.Artifact, error) {
	p.initializeMetadata()

	contentStr := string(content)
	p.detectLicenseType(contentStr)
	p.extractLicenseInfo(contentStr)

	return []artifact.Artifact{p.createArtifact()}, nil
}

// initializeMetadata sets up basic metadata
func (p *licenseParser) initializeMetadata() {
	p.metadata = map[string]string{
		"security_type": "license",
		"file_type":     strings.ToLower(filepath.Ext(p.path)),
		"filename":      p.info.Name(),
	}
}

// detectLicenseType attempts to identify the license type from content
func (p *licenseParser) detectLicenseType(content string) {
	contentLower := strings.ToLower(content)

	// Common license identifiers
	licensePatterns := map[string]string{
		"mit":       "MIT License",
		"apache":    "Apache License",
		"gpl":       "GNU General Public License",
		"bsd":       "BSD License",
		"mozilla":   "Mozilla Public License",
		"lgpl":      "GNU Lesser General Public License",
		"creative":  "Creative Commons",
		"unlicense": "Unlicense",
		"isc":       "ISC License",
		"eclipse":   "Eclipse Public License",
	}

	for pattern, licenseType := range licensePatterns {
		if strings.Contains(contentLower, pattern) {
			p.metadata["license_type"] = licenseType
			p.metadata["detected_keyword"] = pattern
			break
		}
	}

	// If no specific license detected, mark as unknown
	if _, exists := p.metadata["license_type"]; !exists {
		p.metadata["license_type"] = "Unknown"
	}
}

// extractLicenseInfo extracts additional license information
func (p *licenseParser) extractLicenseInfo(content string) {
	lines := strings.Split(content, "\n")

	// Look for copyright information
	for _, line := range lines {
		lineLower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lineLower, "copyright") {
			p.metadata["copyright_line"] = strings.TrimSpace(line)
			p.extractCopyrightYear(line)
			break
		}
	}

	// Calculate content statistics
	p.metadata["line_count"] = string(rune(len(lines)))
	p.metadata["char_count"] = string(rune(len(content)))

	// Check if it's a standard license file location
	if strings.ToUpper(p.info.Name()) == "LICENSE" ||
		strings.HasPrefix(strings.ToUpper(p.info.Name()), "LICENSE.") {
		p.metadata["is_standard_location"] = "true"
	} else {
		p.metadata["is_standard_location"] = "false"
	}
}

// extractCopyrightYear attempts to extract year from copyright line
func (p *licenseParser) extractCopyrightYear(copyrightLine string) {
	// Simple pattern to find 4-digit years
	words := strings.Fields(copyrightLine)
	for _, word := range words {
		// Remove common punctuation
		cleaned := strings.Trim(word, "(),")
		if len(cleaned) == 4 && cleaned >= "1900" && cleaned <= "2030" {
			p.metadata["copyright_year"] = cleaned
			break
		}
		// Handle year ranges like "2020-2023"
		if strings.Contains(cleaned, "-") && len(cleaned) == 9 {
			years := strings.Split(cleaned, "-")
			if len(years) == 2 && len(years[0]) == 4 && len(years[1]) == 4 {
				p.metadata["copyright_year_range"] = cleaned
				break
			}
		}
	}
}

// createArtifact creates the final artifact
func (p *licenseParser) createArtifact() artifact.Artifact {
	modTime := p.info.ModTime()
	relPath, _ := filepath.Rel(p.source.Location, p.path)

	return artifact.Artifact{
		Name:        p.info.Name(),
		Type:        artifact.TypeLicense,
		Path:        relPath,
		Source:      p.source,
		Size:        p.info.Size(),
		Permissions: p.info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    p.metadata,
	}
}

// createBasicLicenseArtifact creates a basic license artifact when parsing fails
func (l *LicenseScanner) createBasicLicenseArtifact(path string, source artifact.Source, info os.FileInfo) artifact.Artifact {
	metadata := map[string]string{
		"security_type": "license",
		"file_type":     strings.ToLower(filepath.Ext(path)),
		"filename":      info.Name(),
		"parse_error":   "true",
	}

	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeLicense,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}
}
