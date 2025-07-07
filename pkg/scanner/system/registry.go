package system

import (
	"github.com/jhumel-code/artiscanctl/pkg/scanner/core"
)

// GetSystemRegistry returns a registry with all system scanners pre-registered
func GetSystemRegistry() *core.ScannerRegistry {
	registry := core.NewScannerRegistry()

	// Register all system scanners
	registry.RegisterScanner(NewBinaryScanner())
	registry.RegisterScanner(NewServiceScanner())
	registry.RegisterScanner(NewConfigScanner())

	return registry
}
