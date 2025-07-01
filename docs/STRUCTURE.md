# Project Structure

```
cartographer/
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions CI/CD pipeline
├── api/                            # API definitions (future)
├── bin/                            # Compiled binaries (gitignored)
├── cmd/
│   └── cartographer/
│       └── main.go                 # Main CLI application
├── docs/                           # Documentation (future)
├── internal/                       # Private application code (future)
├── pkg/
│   ├── artifact/
│   │   ├── types.go               # Core artifact types and interfaces
│   │   └── types_test.go          # Tests for artifact types
│   ├── docker/
│   │   └── client.go              # Docker client using go-containerregistry
│   └── scanner/
│       ├── basic.go               # Basic file system scanners
│       └── manager.go             # Scanner orchestration
├── test/                          # Test data and integration tests (future)
├── .gitignore                     # Git ignore patterns
├── ARTIFACTS.md                   # Comprehensive list of supported artifacts
├── Dockerfile                     # Container build file
├── LICENSE                        # MIT license
├── Makefile                       # Build automation
├── README.md                      # Project documentation
├── ROADMAP.md                     # Development roadmap
├── go.mod                         # Go module definition
└── go.sum                         # Go module checksums
```

## Key Components

### `/cmd/cartographer/main.go`
The main CLI application that:
- Parses command line arguments
- Initializes the Docker client and scanner manager
- Orchestrates scanning operations
- Outputs results in JSON format

### `/pkg/artifact/types.go`
Core data structures including:
- `Artifact` - Represents any software artifact found during scanning
- `Collection` - Groups artifacts from a single scan operation
- `Scanner` interface - Defines how scanners should work
- `Repository` interface - Defines artifact storage (future)

### `/pkg/docker/client.go`
Docker integration using google/go-containerregistry:
- Pull Docker images from registries
- Load images from tar files
- Extract layer information and metadata
- Provide layer content streams for scanning

### `/pkg/scanner/`
Scanner implementations:
- `manager.go` - Orchestrates multiple scanners
- `basic.go` - Basic file system scanners for packages, binaries, configs

## Current Capabilities

✅ **Working Features:**
- Docker image pulling and analysis
- Basic file system scanning
- Debian package detection (dpkg)
- Binary and shared library detection
- Configuration file detection
- JSON output format

🔄 **In Progress:**
- Layer-by-layer Docker image scanning
- More package manager support
- Vulnerability detection
- SBOM generation

## Usage Examples

```bash
# Build the project
make build

# Scan a Docker image
./bin/cartographer scan image nginx:latest

# Scan a local filesystem
./bin/cartographer scan filesystem /usr/local

# Run tests
make test

# Clean build artifacts
make clean
```
