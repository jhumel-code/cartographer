# Artiscanctl

A comprehensive software artifact scanning and analysis tool for Docker images and filesystems. Artiscanctl automatically detects packages, dependencies, and software components to provide detailed insights into your software supply chain.

## Supported Artifact Types

> **Note**: This section distinguishes between fully implemented scanners (✅), partially implemented/placeholder scanners (🟡), and planned future implementations (📋).

### Language Package Managers - **FULLY IMPLEMENTED** ✅
These package managers have complete scanner implementations with real parsing logic:

- **Node.js**: NPM (`package.json`, `package-lock.json`), Yarn (`yarn.lock`)
- **Python**: Pip (`requirements.txt`), Poetry (`poetry.lock`), Conda (`environment.yml`)
- **Java**: Maven (`pom.xml`)
- **Go**: Go modules (`go.mod`, `go.sum`)
- **Rust**: Cargo (`Cargo.toml`, `Cargo.lock`)
- **Ruby**: RubyGems (`Gemfile`, `Gemfile.lock`, `*.gemspec`)
- **PHP**: Composer (`composer.json`, `composer.lock`)

### System & Binary Analysis - **FULLY IMPLEMENTED** ✅
These scanners have complete implementations with real analysis logic:

- **Binary Files**: Executables (`.exe`, `/bin/*`, `/sbin/*`), shared libraries (`.so`, `.dll`, `.dylib`)
- **System Services**: systemd service files (`.service`)
- **Configuration Files**: JSON, YAML, INI, properties, TOML, XML configs

### Infrastructure as Code - **PARTIALLY IMPLEMENTED** 🟡
- **Docker**: ✅ **Fully implemented** - Dockerfile parsing (base images, ports, user, workdir, entrypoint, cmd) and docker-compose.yml parsing (services, networks, volumes)
- **Kubernetes**: 🟡 **Placeholder** - File detection only, no parsing logic
- **Terraform**: 🟡 **Placeholder** - File detection only, no parsing logic  
- **Ansible**: 🟡 **Placeholder** - File detection only, no parsing logic

### Security Artifacts - **PARTIALLY IMPLEMENTED** 🟡
- **Certificates**: ✅ **Implemented** - PEM/DER certificate parsing with metadata extraction
- **Private Keys**: ✅ **Implemented** - RSA/ECDSA key detection and metadata
- **License Files**: ✅ **Implemented** - License detection and SPDX mapping

### Planned Future Implementations 📋
The following artifact types are defined in the codebase but do not yet have scanner implementations:

#### Additional Package Managers
- **.NET**: NuGet packages
- **Haskell**: Cabal, Stack packages  
- **Swift**: Swift Package Manager
- **Dart**: Pub packages
- **iOS/macOS**: CocoaPods, Carthage
- **C/C++**: Conan, vcpkg packages
- **R**: CRAN packages
- **Elixir/Erlang**: Hex packages

#### System Package Managers
- **Linux**: dpkg (Debian/Ubuntu), RPM (Red Hat/CentOS/Fedora), apk (Alpine)
- **Universal**: Snap, Flatpak, AppImage packages

#### Build Systems & CI/CD
- **Build Tools**: Makefiles, CMake, Meson, Bazel, SBT, Gradle wrapper
- **CI/CD**: GitHub Actions, GitLab CI, CircleCI, Travis CI, Azure Pipelines

#### Documentation & Web Assets
- **Documentation**: README files, changelogs, man pages
- **API Specs**: OpenAPI/Swagger, GraphQL schemas
- **Web Assets**: HTML, CSS, JavaScript files

## Output Format

Artiscanctl outputs JSON reports with detected artifacts:

```json
{
  "id": "scan-abc123",
  "source": {
    "type": "docker-image",
    "location": "node:18-alpine",
    "metadata": {
      "registry": "docker.io",
      "repository": "library/node",
      "tag": "18-alpine"
    }
  },
  "scan_time": "2025-07-06T12:00:00Z",
  "artifacts": [
    {
      "id": "npm-express-4.18.2",
      "name": "express",
      "version": "4.18.2",
      "type": "npm-package",
      "path": "/app/package-lock.json",
      "metadata": {
        "package_manager": "npm",
        "source_file": "package-lock.json",
        "dependency_type": "production",
        "license": "MIT"
      }
    },
    {
      "id": "go-gin-v1.9.1",
      "name": "github.com/gin-gonic/gin",
      "version": "v1.9.1",
      "type": "go-module",
      "path": "/app/go.mod",
      "metadata": {
        "package_manager": "go",
        "source_file": "go.mod",
        "is_main_module": "false"
      }
    },
    {
      "id": "dockerfile-main",
      "name": "Dockerfile",
      "type": "dockerfile",
      "path": "/app/Dockerfile",
      "metadata": {
        "base_images": "node:18-alpine",
        "exposed_ports": "3000",
        "workdir": "/app",
        "user": "node"
      }
    }
  ],
  "summary": {
    "total_artifacts": 3,
    "artifact_types": {
      "npm-package": 1,
      "go-module": 1,
      "dockerfile": 1
    }
  },
  "metadata": {
    "scanner_version": "2.0.0-artiscanctl",
    "scan_duration": "1.234s"
  }
}
```

## Examples

### Extract Package Information
```bash
# Scan a Node.js application
artiscanctl scan image node:18-alpine

# Scan local project
artiscanctl scan filesystem ./my-project

# Filter specific package types
artiscanctl scan filesystem . | jq '.artifacts[] | select(.type == "npm-package")'
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