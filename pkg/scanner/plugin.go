package scanner

import (
	"context"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// Plugin defines the interface for scanner plugins that enhance artifacts
type Plugin interface {
	// Name returns the name of the plugin
	Name() string

	// Priority returns the execution priority (lower numbers execute first)
	Priority() int

	// SupportedTypes returns the artifact types this plugin can process
	SupportedTypes() []artifact.Type

	// Process enhances artifacts with additional metadata or relationships
	Process(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error)
}

// PluginRegistry manages scanner plugins
type PluginRegistry struct {
	plugins []Plugin
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make([]Plugin, 0),
	}
}

// Register adds a plugin to the registry
func (r *PluginRegistry) Register(plugin Plugin) {
	// Insert plugin in priority order (lower priority numbers first)
	inserted := false
	for i, p := range r.plugins {
		if plugin.Priority() < p.Priority() {
			// Insert at position i
			r.plugins = append(r.plugins[:i], append([]Plugin{plugin}, r.plugins[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		r.plugins = append(r.plugins, plugin)
	}
}

// GetPlugins returns all registered plugins
func (r *PluginRegistry) GetPlugins() []Plugin {
	return r.plugins
}

// GetPluginsForType returns plugins that support the given artifact type
func (r *PluginRegistry) GetPluginsForType(artifactType artifact.Type) []Plugin {
	var supportedPlugins []Plugin

	for _, plugin := range r.plugins {
		for _, supportedType := range plugin.SupportedTypes() {
			if supportedType == artifactType {
				supportedPlugins = append(supportedPlugins, plugin)
				break
			}
		}
	}

	return supportedPlugins
}

// ProcessArtifacts runs all applicable plugins on the artifacts
func (r *PluginRegistry) ProcessArtifacts(ctx context.Context, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	processedArtifacts := artifacts

	for _, plugin := range r.plugins {
		enhanced, err := r.processWithPlugin(ctx, plugin, processedArtifacts)
		if err != nil {
			// Continue with unprocessed artifacts if plugin fails
			continue
		}
		processedArtifacts = enhanced
	}

	return processedArtifacts, nil
}

// processWithPlugin processes artifacts with a single plugin
func (r *PluginRegistry) processWithPlugin(ctx context.Context, plugin Plugin, artifacts []artifact.Artifact) ([]artifact.Artifact, error) {
	applicable, nonApplicable := r.separateArtifactsBySupport(plugin, artifacts)

	if len(applicable) == 0 {
		return artifacts, nil
	}

	enhanced, err := plugin.Process(ctx, applicable)
	if err != nil {
		return artifacts, err
	}

	return append(nonApplicable, enhanced...), nil
}

// separateArtifactsBySupport separates artifacts based on plugin support
func (r *PluginRegistry) separateArtifactsBySupport(plugin Plugin, artifacts []artifact.Artifact) (applicable, nonApplicable []artifact.Artifact) {
	for _, art := range artifacts {
		if r.isArtifactSupported(plugin, art) {
			applicable = append(applicable, art)
		} else {
			nonApplicable = append(nonApplicable, art)
		}
	}
	return applicable, nonApplicable
}

// isArtifactSupported checks if a plugin supports an artifact type
func (r *PluginRegistry) isArtifactSupported(plugin Plugin, art artifact.Artifact) bool {
	for _, supportedType := range plugin.SupportedTypes() {
		if art.Type == supportedType {
			return true
		}
	}
	return false
}
