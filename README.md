# Cartographer

A comprehensive software artifact scanning and analysis tool for Docker images and filesystems. Cartographer maps out dependencies, security vulnerabilities, licenses, and infrastructure components to provide detailed insights into your software supply chain.

## Features

### 🔍 **Multi-Source Scanning**
- **Docker Images**: Analyze container images layer by layer
- **Filesystems**: Scan local directories and files

### 📦 **Artifact Detection**
- **Package Managers**: npm, pip, Go modules, Maven, Gradle, Composer, and more
- **System Packages**: apt, yum, apk, pacman, and other distribution packages
- **Binary Analysis**: Executables, shared libraries, system services
- **Language-Specific**: Detect and analyze language-specific dependencies

### 🛡️ **Security Analysis**
- **Vulnerability Detection**: Identify known security vulnerabilities
- **Secret Scanning**: Detect exposed API keys, tokens, and credentials
- **Certificate Analysis**: Find and analyze SSL/TLS certificates
- **Security Configuration**: Analyze security-related configurations

### 📋 **License Compliance**
- **License Detection**: Identify software licenses across all components
- **Compliance Reporting**: Generate license compliance reports
- **Risk Assessment**: Highlight potential license compatibility issues

### 🏗️ **Infrastructure Analysis**
- **CI/CD Detection**: Identify build and deployment configurations
- **Container Analysis**: Docker, Kubernetes, and container orchestration files
- **Cloud Resources**: Detect cloud service configurations

### 🔗 **Relationship Mapping**
- **Dependency Trees**: Map complex dependency relationships
- **Component Interactions**: Understand how components interact
- **Supply Chain Visualization**: Get a complete view of your software supply chain

## Installation

### Download Binary
```bash
# Download the latest release
curl -L https://github.com/ianjhumelbautista/cartographer/releases/latest/download/cartographer-linux-amd64 -o cartographer
chmod +x cartographer
```

### Build from Source
```bash
# Clone the repository
git clone https://github.com/ianjhumelbautista/cartographer.git
cd cartographer

# Build the binary
make build

# Install globally (optional)
make install
```

### Using Docker
```bash
# Run directly with Docker
docker run --rm -v $(pwd):/workspace cartographer:latest scan filesystem /workspace
```

## Usage

### Basic Commands

#### Scan a Docker Image
```bash
# Scan a specific image
cartographer scan image nginx:latest

# Scan a private registry image
cartographer scan image registry.example.com/myapp:v1.2.3
```

#### Scan a Filesystem
```bash
# Scan current directory
cartographer scan filesystem .

# Scan specific path
cartographer scan filesystem /usr/local

# Scan a project directory
cartographer scan filesystem ./my-project
```

### Output Format

Cartographer outputs detailed JSON reports containing:

```json
{
  "metadata": {
    "scan_id": "unique-scan-identifier",
    "timestamp": "2025-07-01T12:00:00Z",
    "target": "nginx:latest",
    "scan_type": "image"
  },
  "artifacts": [
    {
      "id": "artifact-id",
      "type": "debian-package",
      "name": "openssl",
      "version": "1.1.1f-1ubuntu2.20",
      "locations": ["/var/lib/dpkg/status"],
      "metadata": {
        "architecture": "amd64",
        "description": "Secure Sockets Layer toolkit"
      }
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "severity": "HIGH",
      "artifact_id": "artifact-id",
      "description": "Buffer overflow vulnerability",
      "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"]
    }
  ],
  "licenses": [
    {
      "artifact_id": "artifact-id",
      "license": "Apache-2.0",
      "confidence": 0.95,
      "source": "package-metadata"
    }
  ],
  "relationships": [
    {
      "source": "source-artifact-id",
      "target": "target-artifact-id",
      "type": "depends-on",
      "metadata": {}
    }
  ]
}
```

## Examples

### Scanning a Web Application
```bash
# Scan a Node.js application container
cartographer scan image node:18-alpine

# Scan the source code
cartographer scan filesystem ./my-webapp
```

### Security-Focused Scanning
```bash
# Scan for security vulnerabilities and secrets
cartographer scan image myapp:latest | jq '.vulnerabilities, .secrets'

# Focus on high-severity issues
cartographer scan filesystem . | jq '.vulnerabilities[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
```

### License Compliance
```bash
# Extract license information
cartographer scan filesystem . | jq '.licenses[] | {artifact: .artifact_id, license: .license}'

# Find GPL licenses
cartographer scan image myapp:latest | jq '.licenses[] | select(.license | contains("GPL"))'
```

## Supported Package Types

### System Packages
- **Debian/Ubuntu**: dpkg, apt
- **Red Hat/CentOS/Fedora**: rpm, yum, dnf
- **Alpine**: apk
- **Arch Linux**: pacman
- **SUSE**: zypper
- **Gentoo**: portage

### Language Package Managers
- **JavaScript/Node.js**: npm, yarn, pnpm
- **Python**: pip, conda, poetry
- **Go**: go modules
- **Java**: Maven, Gradle
- **.NET**: NuGet
- **PHP**: Composer
- **Ruby**: RubyGems, Bundler
- **Rust**: Cargo
- **Swift**: Swift Package Manager
- **Dart/Flutter**: pub

### Container & Infrastructure
- **Docker**: Dockerfile, docker-compose
- **Kubernetes**: YAML manifests, Helm charts
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins
- **Infrastructure as Code**: Terraform, CloudFormation

## Development

### Prerequisites
- Go 1.23 or later
- Docker (for container scanning)
- Make

### Building
```bash
# Install dependencies
go mod download

# Run tests
make test

# Build binary
make build

# Build Docker image
make docker-build
```

### Running Tests
```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test package
go test ./pkg/scanner/...
```

### Code Quality
```bash
# Format code
make format

# Run linter
make lint

# Run security checks
make security-check
```

## Architecture

Cartographer follows a modular architecture with pluggable scanners:

```
├── cmd/cartographer/           # CLI application
├── pkg/
│   ├── artifact/              # Core artifact types and interfaces
│   ├── docker/                # Docker client and image handling
│   └── scanner/               # Scanner implementations
│       ├── manager.go         # Scanner coordination
│       ├── binary_analyzer.go # Binary and executable analysis
│       ├── dependency_analyzer.go # Package dependency analysis
│       ├── security_analyzer.go   # Security and vulnerability scanning
│       ├── license_analyzer.go    # License detection and analysis
│       └── infrastructure_analyzer.go # Infrastructure configuration analysis
```

### Key Components

- **Scanner Manager**: Orchestrates multiple specialized scanners
- **Artifact Types**: Comprehensive type system for software artifacts
- **Docker Client**: Container image analysis using go-containerregistry
- **Analyzers**: Specialized components for different analysis types

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`make test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/ianjhumelbautista/cartographer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ianjhumelbautista/cartographer/discussions)

---

**Cartographer** - Map your software supply chain with confidence.