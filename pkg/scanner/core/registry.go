package core

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// ScannerRegistry manages all available scanners
type ScannerRegistry struct {
	scanners      map[string]Scanner
	layerScanners map[string]LayerScanner
	mutex         sync.RWMutex
}

// NewScannerRegistry creates a new scanner registry
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		scanners:      make(map[string]Scanner),
		layerScanners: make(map[string]LayerScanner),
	}
}

// RegisterScanner registers a scanner with the registry
func (r *ScannerRegistry) RegisterScanner(scanner Scanner) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.scanners[scanner.Name()] = scanner

	// Also register as layer scanner if it implements the interface
	if layerScanner, ok := scanner.(LayerScanner); ok {
		r.layerScanners[scanner.Name()] = layerScanner
	}
}

// UnregisterScanner removes a scanner from the registry
func (r *ScannerRegistry) UnregisterScanner(name string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	delete(r.scanners, name)
	delete(r.layerScanners, name)
}

// GetScanner retrieves a scanner by name
func (r *ScannerRegistry) GetScanner(name string) (Scanner, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	scanner, exists := r.scanners[name]
	return scanner, exists
}

// GetLayerScanner retrieves a layer scanner by name
func (r *ScannerRegistry) GetLayerScanner(name string) (LayerScanner, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	scanner, exists := r.layerScanners[name]
	return scanner, exists
}

// GetAllScanners returns all registered scanners
func (r *ScannerRegistry) GetAllScanners() []Scanner {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	scanners := make([]Scanner, 0, len(r.scanners))
	for _, scanner := range r.scanners {
		scanners = append(scanners, scanner)
	}

	// Sort by name for consistent ordering
	sort.Slice(scanners, func(i, j int) bool {
		return scanners[i].Name() < scanners[j].Name()
	})

	return scanners
}

// GetAllLayerScanners returns all registered layer scanners
func (r *ScannerRegistry) GetAllLayerScanners() []LayerScanner {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	scanners := make([]LayerScanner, 0, len(r.layerScanners))
	for _, scanner := range r.layerScanners {
		scanners = append(scanners, scanner)
	}

	return scanners
}

// GetScannersByType returns scanners that support the given artifact type
func (r *ScannerRegistry) GetScannersByType(artifactType artifact.Type) []Scanner {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var matchingScanners []Scanner
	for _, scanner := range r.scanners {
		for _, supportedType := range scanner.SupportedTypes() {
			if supportedType == artifactType {
				matchingScanners = append(matchingScanners, scanner)
				break
			}
		}
	}

	return matchingScanners
}

// GetScannerNames returns all registered scanner names
func (r *ScannerRegistry) GetScannerNames() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// ScanWithAllScanners executes all registered scanners on the given source
func (r *ScannerRegistry) ScanWithAllScanners(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var allArtifacts []artifact.Artifact
	scanners := r.GetAllScanners()

	for _, scanner := range scanners {
		select {
		case <-ctx.Done():
			return allArtifacts, ctx.Err()
		default:
		}

		artifacts, err := scanner.Scan(ctx, source)
		if err != nil {
			// Log error but continue with other scanners
			continue
		}

		allArtifacts = append(allArtifacts, artifacts...)
	}

	return allArtifacts, nil
}

// ScanWithSelectedScanners executes only the specified scanners
func (r *ScannerRegistry) ScanWithSelectedScanners(ctx context.Context, source artifact.Source, scannerNames []string) ([]artifact.Artifact, error) {
	var allArtifacts []artifact.Artifact

	for _, name := range scannerNames {
		scanner, exists := r.GetScanner(name)
		if !exists {
			return nil, fmt.Errorf("scanner not found: %s", name)
		}

		select {
		case <-ctx.Done():
			return allArtifacts, ctx.Err()
		default:
		}

		artifacts, err := scanner.Scan(ctx, source)
		if err != nil {
			// Log error but continue with other scanners
			continue
		}

		allArtifacts = append(allArtifacts, artifacts...)
	}

	return allArtifacts, nil
}

// ValidateRegistry checks that all scanners are properly configured
func (r *ScannerRegistry) ValidateRegistry() error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if len(r.scanners) == 0 {
		return fmt.Errorf("no scanners registered")
	}

	// Check for duplicate names
	names := make(map[string]bool)
	for name := range r.scanners {
		if names[name] {
			return fmt.Errorf("duplicate scanner name: %s", name)
		}
		names[name] = true
	}

	return nil
}
