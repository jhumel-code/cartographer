# Cartographer

A comprehensive software artifact scanning and analysis tool for Docker images and filesystems. Cartographer automatically detects packages, dependencies, and software components to provide detailed insights into your software supply chain.

## Features

- **Multi-Source Scanning**: Analyze Docker images and filesystem paths
- **Package Detection**: Comprehensive support for system and language package managers
- **Binary Analysis**: Analyze executables, libraries, and system services
- **Dependency Mapping**: Understand relationships between components
- **JSON Output**: Structured results for integration with other tools

## Installation

### Build from Source
```bash
git clone https://github.com/ianjhumelbautista/cartographer.git
cd cartographer
make build
```

## Usage

### Scan a Docker Image
```bash
cartographer scan image nginx:latest
cartographer scan image registry.example.com/myapp:v1.2.3
```

### Scan a Filesystem
```bash
cartographer scan filesystem .
cartographer scan filesystem /usr/local
```

## Supported Package Managers

### System Package Managers
- **Debian/Ubuntu packages** (`dpkg`, `apt`)
- **RPM packages** (RHEL, CentOS, Fedora, SUSE)
- **Alpine packages** (`apk`)
- **Arch Linux packages** (`pacman`)
- **Gentoo packages** (`portage`)
- **Snap packages**
- **Flatpak packages**
- **AppImage packages**

### Language-Specific Package Managers
- **Node.js** (`package.json`, `package-lock.json`, `yarn.lock`)
- **Python** (`requirements.txt`, `Pipfile`, `pyproject.toml`)
- **Go** (`go.mod`, `go.sum`)
- **Rust** (`Cargo.toml`, `Cargo.lock`)
- **Ruby** (`Gemfile`, `Gemfile.lock`)
- **PHP** (`composer.json`, `composer.lock`)
- **Java** (`pom.xml`, `build.gradle`)
- **.NET** (`packages.config`, `packages.lock.json`)
- **Swift** (`Package.swift`)
- **Dart/Flutter** (`pubspec.yaml`)
- **Elixir** (`mix.exs`, `mix.lock`)
- **Haskell** (`stack.yaml`, `cabal.project`)
- **R** (`DESCRIPTION`, `renv.lock`)
- **C/C++** (`conanfile.txt`, `conan.lock`)
- **iOS/macOS** (`Podfile`, `Podfile.lock`)
- **Terraform** (`.tf` files, `terraform.lock.hcl`)

## Output Format

Cartographer outputs JSON reports with detected artifacts:

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
  ]
}
```

## Examples

### Extract Package Information
```bash
# Scan a Node.js application
cartographer scan image node:18-alpine

# Scan local project
cartographer scan filesystem ./my-project

# Filter specific package types
cartographer scan filesystem . | jq '.artifacts[] | select(.type == "npm-package")'
```

## Development

### Building
```bash
go mod download
make build
make test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.