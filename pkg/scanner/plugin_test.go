package scanner

import (
	"context"
	"testing"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/license"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/publishers"
	"github.com/jhumel-code/artiscanctl/pkg/scanner/plugins/security"
)

const (
	testPluginProcessingError = "Plugin processing failed: %v"
)

func TestPluginRegistry(t *testing.T) {
	registry := NewPluginRegistry()

	// Create mock plugins
	plugin1 := &MockPlugin{name: "plugin1", priority: 20}
	plugin2 := &MockPlugin{name: "plugin2", priority: 10}
	plugin3 := &MockPlugin{name: "plugin3", priority: 30}

	// Register plugins
	registry.Register(plugin1)
	registry.Register(plugin2)
	registry.Register(plugin3)

	plugins := registry.GetPlugins()

	// Should be ordered by priority
	if len(plugins) != 3 {
		t.Errorf("Expected 3 plugins, got %d", len(plugins))
	}

	if plugins[0].Priority() != 10 {
		t.Errorf("Expected first plugin priority 10, got %d", plugins[0].Priority())
	}

	if plugins[1].Priority() != 20 {
		t.Errorf("Expected second plugin priority 20, got %d", plugins[1].Priority())
	}

	if plugins[2].Priority() != 30 {
		t.Errorf("Expected third plugin priority 30, got %d", plugins[2].Priority())
	}
}

func TestVendorMappingPlugin(t *testing.T) {
	plugin := publishers.NewVendorMappingPlugin()

	// Create test artifacts
	artifacts := []artifact.Artifact{
		{
			Name: "react",
			Type: artifact.TypeNpmPackage,
		},
		{
			Name: "@microsoft/typescript",
			Type: artifact.TypeNpmPackage,
		},
	}

	enhanced, err := plugin.Process(context.Background(), artifacts)
	if err != nil {
		t.Fatalf(testPluginProcessingError, err)
	}

	if len(enhanced) != 2 {
		t.Errorf("Expected 2 enhanced artifacts, got %d", len(enhanced))
	}

	// Check if vendor metadata was added
	for _, art := range enhanced {
		if art.Metadata == nil {
			t.Error("Expected metadata to be added")
			continue
		}

		if _, exists := art.Metadata["vendor"]; !exists {
			t.Error("Expected vendor metadata to be added")
		}
	}
}

func TestSPDXLicenseMappingPlugin(t *testing.T) {
	plugin := license.NewSPDXLicenseMappingPlugin()

	// Create test artifacts with licenses
	artifacts := []artifact.Artifact{
		{
			Name: "test-package",
			Type: artifact.TypeNpmPackage,
			Licenses: []artifact.License{
				{ID: "MIT", Name: "MIT License"},
				{ID: "apache 2.0", Name: "Apache License 2.0"},
			},
		},
	}

	enhanced, err := plugin.Process(context.Background(), artifacts)
	if err != nil {
		t.Fatalf(testPluginProcessingError, err)
	}

	if len(enhanced) != 1 {
		t.Errorf("Expected 1 enhanced artifact, got %d", len(enhanced))
	}

	art := enhanced[0]
	if len(art.Licenses) != 2 {
		t.Errorf("Expected 2 licenses, got %d", len(art.Licenses))
	}

	// Check SPDX IDs were added
	if art.Licenses[0].SPDXID != "MIT" {
		t.Errorf("Expected SPDX ID 'MIT', got '%s'", art.Licenses[0].SPDXID)
	}

	if art.Licenses[1].SPDXID != "Apache-2.0" {
		t.Errorf("Expected SPDX ID 'Apache-2.0', got '%s'", art.Licenses[1].SPDXID)
	}
}

func TestSecretExtractionPlugin(t *testing.T) {
	plugin := security.NewSecretExtractionPlugin()

	// Create test artifacts with potential secrets
	artifacts := []artifact.Artifact{
		{
			Name: "config.env",
			Type: artifact.TypeEnvironmentFile,
			Path: "/app/.env",
			Metadata: map[string]string{
				"content": "API_KEY=AKIA1234567890123456\nPASSWORD=secretpassword123",
			},
		},
	}

	enhanced, err := plugin.Process(context.Background(), artifacts)
	if err != nil {
		t.Fatalf(testPluginProcessingError, err)
	}

	if len(enhanced) != 1 {
		t.Errorf("Expected 1 enhanced artifact, got %d", len(enhanced))
	}

	art := enhanced[0]
	if art.Metadata["has_secrets"] != "true" {
		t.Error("Expected has_secrets metadata to be 'true'")
	}

	if art.Metadata["secret_types"] == "" {
		t.Error("Expected secret_types metadata to be populated")
	}
}

func TestManagerWithPlugins(t *testing.T) {
	// Create a modular default manager
	manager := NewModularDefaultManager(nil)

	// Check that plugin registry exists
	if manager.GetPluginRegistry() == nil {
		t.Error("Expected plugin registry to be initialized")
	}

	// Check that plugins were registered
	plugins := manager.GetPluginRegistry().GetPlugins()
	if len(plugins) == 0 {
		t.Error("Expected plugins to be registered")
	}

	// Check plugin priority ordering
	for i := 1; i < len(plugins); i++ {
		if plugins[i-1].Priority() > plugins[i].Priority() {
			t.Error("Plugins should be ordered by priority")
		}
	}
}

// MockPlugin for testing
type MockPlugin struct {
	name     string
	priority int
}

func (p *MockPlugin) Name() string {
	return p.name
}

func (p *MockPlugin) Priority() int {
	return p.priority
}

func (p *MockPlugin) SupportedTypes() []artifact.Type {
	return []artifact.Type{artifact.TypeNpmPackage}
}

func (p *MockPlugin) Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	return artifacts, nil
}
