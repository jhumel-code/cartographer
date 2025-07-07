package infrastructure

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
)

// DockerScanner scans for Docker-related files
type DockerScanner struct {
	*core.BaseScanner
}

// NewDockerScanner creates a new Docker scanner
func NewDockerScanner() *DockerScanner {
	patterns := []string{
		"Dockerfile",
		"*.dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"docker-compose.*.yml",
		"docker-compose.*.yaml",
		".dockerignore",
	}

	supportedTypes := []artifact.Type{
		artifact.TypeDockerfile,
		artifact.TypeDockerCompose,
	}

	return &DockerScanner{
		BaseScanner: core.NewBaseScanner("docker-scanner", supportedTypes, patterns),
	}
}

// Scan scans for Docker-related artifacts in the source
func (d *DockerScanner) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	return d.WalkDirectory(ctx, source.Location, source, func(path string, info os.FileInfo) ([]artifact.Artifact, error) {
		filename := strings.ToLower(info.Name())

		if !d.MatchesFile(filename, path) {
			return nil, nil
		}

		switch {
		case filename == "dockerfile" || strings.HasSuffix(filename, ".dockerfile"):
			return d.parseDockerfile(path, source, info)

		case strings.HasPrefix(filename, "docker-compose") && (strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml")):
			return d.parseDockerCompose(path, source, info)

		case filename == ".dockerignore":
			return d.parseDockerIgnore(path, source, info)
		}

		return nil, nil
	})
}

// parseDockerfile parses a Dockerfile and extracts metadata
func (d *DockerScanner) parseDockerfile(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	metadata := map[string]string{
		"iac_type":  "container",
		"platform":  "docker",
		"file_type": "dockerfile",
	}

	parser := &dockerfileParser{}
	parser.parse(file)
	parser.addToMetadata(metadata)

	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	foundArtifact := artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeDockerfile,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}

	return []artifact.Artifact{foundArtifact}, nil
}

// dockerfileParser helps parse Dockerfile content
type dockerfileParser struct {
	baseImages   []string
	exposedPorts []string
	workdir      string
	user         string
	entrypoint   string
	cmd          string
}

// parse processes the Dockerfile content
func (p *dockerfileParser) parse(file *os.File) {
	scanner := bufio.NewScanner(file)

	fromRegex := regexp.MustCompile(`(?i)^FROM\s+([^\s]+)`)
	exposeRegex := regexp.MustCompile(`(?i)^EXPOSE\s+(.+)`)
	workdirRegex := regexp.MustCompile(`(?i)^WORKDIR\s+(.+)`)
	userRegex := regexp.MustCompile(`(?i)^USER\s+(.+)`)
	entrypointRegex := regexp.MustCompile(`(?i)^ENTRYPOINT\s+(.+)`)
	cmdRegex := regexp.MustCompile(`(?i)^CMD\s+(.+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		p.processLine(line, fromRegex, exposeRegex, workdirRegex, userRegex, entrypointRegex, cmdRegex)
	}
}

// processLine processes a single line of the Dockerfile
func (p *dockerfileParser) processLine(line string, fromRegex, exposeRegex, workdirRegex, userRegex, entrypointRegex, cmdRegex *regexp.Regexp) {
	// Extract FROM instructions (base images)
	if matches := fromRegex.FindStringSubmatch(line); matches != nil {
		p.baseImages = append(p.baseImages, matches[1])
		return
	}

	// Extract EXPOSE instructions
	if matches := exposeRegex.FindStringSubmatch(line); matches != nil {
		ports := strings.Fields(matches[1])
		p.exposedPorts = append(p.exposedPorts, ports...)
		return
	}

	// Extract other instructions
	if matches := workdirRegex.FindStringSubmatch(line); matches != nil {
		p.workdir = matches[1]
	} else if matches := userRegex.FindStringSubmatch(line); matches != nil {
		p.user = matches[1]
	} else if matches := entrypointRegex.FindStringSubmatch(line); matches != nil {
		p.entrypoint = matches[1]
	} else if matches := cmdRegex.FindStringSubmatch(line); matches != nil {
		p.cmd = matches[1]
	}
}

// addToMetadata adds parsed information to the metadata
func (p *dockerfileParser) addToMetadata(metadata map[string]string) {
	if len(p.baseImages) > 0 {
		metadata["base_images"] = strings.Join(p.baseImages, ", ")
	}
	if len(p.exposedPorts) > 0 {
		metadata["exposed_ports"] = strings.Join(p.exposedPorts, ", ")
	}
	if p.workdir != "" {
		metadata["workdir"] = p.workdir
	}
	if p.user != "" {
		metadata["user"] = p.user
	}
	if p.entrypoint != "" {
		metadata["entrypoint"] = p.entrypoint
	}
	if p.cmd != "" {
		metadata["cmd"] = p.cmd
	}
}

// parseDockerCompose parses docker-compose files
func (d *DockerScanner) parseDockerCompose(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	metadata := map[string]string{
		"iac_type":  "container-orchestration",
		"platform":  "docker-compose",
		"file_type": "yaml",
	}

	// Parse YAML content to extract basic information
	file, err := os.Open(path)
	if err != nil {
		return []artifact.Artifact{d.createBasicDockerComposeArtifact(path, source, info, metadata)}, nil
	}
	defer file.Close()

	parser := &dockerComposeParser{}
	parser.parse(file)
	parser.addToMetadata(metadata)

	return []artifact.Artifact{d.createBasicDockerComposeArtifact(path, source, info, metadata)}, nil
}

// dockerComposeParser helps parse docker-compose YAML content
type dockerComposeParser struct {
	services []string
	networks []string
	volumes  []string
}

// parse processes the docker-compose YAML content
func (p *dockerComposeParser) parse(file *os.File) {
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		currentSection = p.detectSection(line, currentSection)
		p.extractNames(line, currentSection)
	}
}

// detectSection identifies which top-level section we're in
func (p *dockerComposeParser) detectSection(line, currentSection string) string {
	// Detect top-level sections
	if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
		section := strings.TrimSuffix(line, ":")
		switch section {
		case "services", "networks", "volumes":
			return section
		default:
			return ""
		}
	}
	return currentSection
}

// extractNames extracts service, network, or volume names
func (p *dockerComposeParser) extractNames(line, currentSection string) {
	if currentSection == "" {
		return
	}

	// Extract names from indented lines ending with ":"
	if (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) && strings.HasSuffix(line, ":") {
		name := strings.TrimSpace(strings.TrimSuffix(line, ":"))
		if name != "" {
			switch currentSection {
			case "services":
				p.services = append(p.services, name)
			case "networks":
				p.networks = append(p.networks, name)
			case "volumes":
				p.volumes = append(p.volumes, name)
			}
		}
	}
}

// addToMetadata adds parsed information to the metadata
func (p *dockerComposeParser) addToMetadata(metadata map[string]string) {
	if len(p.services) > 0 {
		metadata["services"] = strings.Join(p.services, ", ")
		metadata["service_count"] = string(rune(len(p.services)))
	}
	if len(p.networks) > 0 {
		metadata["networks"] = strings.Join(p.networks, ", ")
	}
	if len(p.volumes) > 0 {
		metadata["volumes"] = strings.Join(p.volumes, ", ")
	}
}

// createBasicDockerComposeArtifact creates a docker-compose artifact
func (d *DockerScanner) createBasicDockerComposeArtifact(path string, source artifact.Source, info os.FileInfo, metadata map[string]string) artifact.Artifact {
	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	return artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeDockerCompose,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}
}

// parseDockerIgnore parses .dockerignore files
func (d *DockerScanner) parseDockerIgnore(path string, source artifact.Source, info os.FileInfo) ([]artifact.Artifact, error) {
	metadata := map[string]string{
		"config_type": "docker-ignore",
		"platform":    "docker",
	}

	modTime := info.ModTime()
	relPath, _ := filepath.Rel(source.Location, path)

	foundArtifact := artifact.Artifact{
		Name:        info.Name(),
		Type:        artifact.TypeConfigFile,
		Path:        relPath,
		Source:      source,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     &modTime,
		Metadata:    metadata,
	}

	return []artifact.Artifact{foundArtifact}, nil
}

// CanScan determines if this scanner can handle the given file
func (d *DockerScanner) CanScan(path string, filename string) bool {
	return d.MatchesFile(filename, path)
}
