package docker

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// fakeLayer implements v1.Layer for testing
type fakeLayer struct {
	digest     v1.Hash
	size       int64
	mediaType  types.MediaType
	compressed io.ReadCloser
}

func (f *fakeLayer) Digest() (v1.Hash, error) {
	return f.digest, nil
}

func (f *fakeLayer) DiffID() (v1.Hash, error) {
	return f.digest, nil
}

func (f *fakeLayer) Size() (int64, error) {
	return f.size, nil
}

func (f *fakeLayer) MediaType() (types.MediaType, error) {
	return f.mediaType, nil
}

func (f *fakeLayer) Compressed() (io.ReadCloser, error) {
	return f.compressed, nil
}

func (f *fakeLayer) Uncompressed() (io.ReadCloser, error) {
	return f.compressed, nil
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name     string
		opts     ClientOptions
		expected ClientOptions
	}{
		{
			name: "default options",
			opts: ClientOptions{},
			expected: ClientOptions{
				Authenticator: authn.Anonymous,
				UserAgent:     "cartographer/1.0",
				Insecure:      false,
			},
		},
		{
			name: "custom options",
			opts: ClientOptions{
				Authenticator: authn.FromConfig(authn.AuthConfig{Username: "test", Password: "pass"}),
				UserAgent:     "custom-agent/2.0",
				Insecure:      true,
			},
			expected: ClientOptions{
				Authenticator: authn.FromConfig(authn.AuthConfig{Username: "test", Password: "pass"}),
				UserAgent:     "custom-agent/2.0",
				Insecure:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.opts)

			if client == nil {
				t.Fatal("NewClient returned nil")
			}

			if client.options.UserAgent != tt.expected.UserAgent {
				t.Errorf("Expected UserAgent %q, got %q", tt.expected.UserAgent, client.options.UserAgent)
			}

			if client.options.Insecure != tt.expected.Insecure {
				t.Errorf("Expected Insecure %v, got %v", tt.expected.Insecure, client.options.Insecure)
			}

			// Test that authenticator is set (we can't easily compare the actual values)
			if client.options.Authenticator == nil {
				t.Error("Expected Authenticator to be set")
			}
		})
	}
}

func TestGetTag(t *testing.T) {
	tests := []struct {
		name     string
		refStr   string
		expected string
	}{
		{
			name:     "tagged reference",
			refStr:   "nginx:latest",
			expected: "latest",
		},
		{
			name:     "tagged reference with registry",
			refStr:   "docker.io/library/nginx:1.20",
			expected: "1.20",
		},
		{
			name:     "digest reference",
			refStr:   "nginx@sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.refStr)
			if err != nil {
				t.Fatalf("Failed to parse reference: %v", err)
			}

			result := getTag(ref)
			if result != tt.expected {
				t.Errorf("Expected tag %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExtractImageInfo(t *testing.T) {
	// Create a fake image for testing
	fakeImage := &fake.FakeImage{
		ConfigFileStub: func() (*v1.ConfigFile, error) {
			return &v1.ConfigFile{
				Architecture: "amd64",
				OS:           "linux",
				Created:      v1.Time{Time: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
				Config: v1.Config{
					User:       "nobody",
					Env:        []string{"PATH=/usr/bin", "HOME=/home/user"},
					Entrypoint: []string{"/entrypoint.sh"},
					Cmd:        []string{"nginx", "-g", "daemon off;"},
					WorkingDir: "/app",
					Labels: map[string]string{
						"version":    "1.0",
						"maintainer": "test@example.com",
					},
					ExposedPorts: map[string]struct{}{
						"80/tcp": {},
					},
					Volumes: map[string]struct{}{
						"/data": {},
					},
				},
				History: []v1.History{
					{
						CreatedBy:  "RUN apt-get update",
						Comment:    "Update packages",
						EmptyLayer: false,
					},
					{
						CreatedBy:  "COPY . /app",
						Comment:    "Copy application",
						EmptyLayer: false,
					},
				},
			}, nil
		},
		SizeStub: func() (int64, error) {
			return 1024000, nil
		},
		DigestStub: func() (v1.Hash, error) {
			return v1.Hash{
				Algorithm: "sha256",
				Hex:       "abc123def456",
			}, nil
		},
		ManifestStub: func() (*v1.Manifest, error) {
			return &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.DockerManifestSchema2,
			}, nil
		},
		LayersStub: func() ([]v1.Layer, error) {
			return []v1.Layer{
				&fakeLayer{
					digest:     v1.Hash{Algorithm: "sha256", Hex: "layer1hash"},
					size:       512000,
					mediaType:  types.DockerLayer,
					compressed: io.NopCloser(strings.NewReader("layer1 content")),
				},
				&fakeLayer{
					digest:     v1.Hash{Algorithm: "sha256", Hex: "layer2hash"},
					size:       512000,
					mediaType:  types.DockerLayer,
					compressed: io.NopCloser(strings.NewReader("layer2 content")),
				},
			}, nil
		},
	}

	client := NewClient(ClientOptions{})
	ref, err := name.ParseReference("nginx:latest")
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	info, err := client.extractImageInfo(ref, fakeImage)
	if err != nil {
		t.Fatalf("extractImageInfo failed: %v", err)
	}

	// Verify basic image info
	if info.Registry != "index.docker.io" {
		t.Errorf("Expected registry 'index.docker.io', got %q", info.Registry)
	}

	if info.Repository != "library/nginx" {
		t.Errorf("Expected repository 'library/nginx', got %q", info.Repository)
	}

	if info.Tag != "latest" {
		t.Errorf("Expected tag 'latest', got %q", info.Tag)
	}

	if info.Architecture != "amd64" {
		t.Errorf("Expected architecture 'amd64', got %q", info.Architecture)
	}

	if info.OS != "linux" {
		t.Errorf("Expected OS 'linux', got %q", info.OS)
	}

	if info.Size != 1024000 {
		t.Errorf("Expected size 1024000, got %d", info.Size)
	}

	if info.Digest != "sha256:abc123def456" {
		t.Errorf("Expected digest 'sha256:abc123def456', got %q", info.Digest)
	}

	// Verify config
	if info.Config == nil {
		t.Fatal("Expected Config to be set")
	}

	if info.Config.User != "nobody" {
		t.Errorf("Expected user 'nobody', got %q", info.Config.User)
	}

	if len(info.Config.Env) != 2 {
		t.Errorf("Expected 2 environment variables, got %d", len(info.Config.Env))
	}

	if info.Config.WorkingDir != "/app" {
		t.Errorf("Expected working directory '/app', got %q", info.Config.WorkingDir)
	}

	// Verify labels
	if info.Labels["version"] != "1.0" {
		t.Errorf("Expected label version '1.0', got %q", info.Labels["version"])
	}

	// Verify layers
	if len(info.Layers) != 2 {
		t.Fatalf("Expected 2 layers, got %d", len(info.Layers))
	}

	layer1 := info.Layers[0]
	if layer1.Digest != "sha256:layer1hash" {
		t.Errorf("Expected layer 1 digest 'sha256:layer1hash', got %q", layer1.Digest)
	}

	if layer1.Size != 512000 {
		t.Errorf("Expected layer 1 size 512000, got %d", layer1.Size)
	}

	if layer1.CreatedBy != "RUN apt-get update" {
		t.Errorf("Expected layer 1 created by 'RUN apt-get update', got %q", layer1.CreatedBy)
	}

	if layer1.Comment != "Update packages" {
		t.Errorf("Expected layer 1 comment 'Update packages', got %q", layer1.Comment)
	}
}

func TestGetLayerContent(t *testing.T) {
	client := NewClient(ClientOptions{})

	// Create a fake layer with content
	content := "test layer content"
	fakeLayer := &fakeLayer{
		compressed: io.NopCloser(strings.NewReader(content)),
	}

	rc, err := client.GetLayerContent(fakeLayer)
	if err != nil {
		t.Fatalf("GetLayerContent failed: %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read layer content: %v", err)
	}

	if string(data) != content {
		t.Errorf("Expected content %q, got %q", content, string(data))
	}
}

// errorLayer implements v1.Layer for testing error conditions
type errorLayer struct {
	err error
}

func (e *errorLayer) Digest() (v1.Hash, error)             { return v1.Hash{}, e.err }
func (e *errorLayer) DiffID() (v1.Hash, error)             { return v1.Hash{}, e.err }
func (e *errorLayer) Size() (int64, error)                 { return 0, e.err }
func (e *errorLayer) MediaType() (types.MediaType, error)  { return "", e.err }
func (e *errorLayer) Compressed() (io.ReadCloser, error)   { return nil, e.err }
func (e *errorLayer) Uncompressed() (io.ReadCloser, error) { return nil, e.err }

func TestGetLayerContentError(t *testing.T) {
	client := NewClient(ClientOptions{})

	// Create a fake layer that returns an error
	expectedError := fmt.Errorf("layer content error")
	fakeLayer := &errorLayer{err: expectedError}

	_, err := client.GetLayerContent(fakeLayer)
	if err == nil {
		t.Fatal("Expected error but got none")
	}

	if err != expectedError {
		t.Errorf("Expected error %v, got %v", expectedError, err)
	}
}

func TestExtractImageInfoErrors(t *testing.T) {
	client := NewClient(ClientOptions{})
	ref, err := name.ParseReference("nginx:latest")
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	tests := []struct {
		name        string
		image       v1.Image
		expectError bool
		errorSubstr string
	}{
		{
			name: "manifest error",
			image: &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return nil, fmt.Errorf("manifest error")
				},
			},
			expectError: true,
			errorSubstr: "getting manifest",
		},
		{
			name: "config error",
			image: &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return &v1.Manifest{}, nil
				},
				ConfigFileStub: func() (*v1.ConfigFile, error) {
					return nil, fmt.Errorf("config error")
				},
			},
			expectError: true,
			errorSubstr: "getting config",
		},
		{
			name: "size error",
			image: &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return &v1.Manifest{}, nil
				},
				ConfigFileStub: func() (*v1.ConfigFile, error) {
					return &v1.ConfigFile{}, nil
				},
				SizeStub: func() (int64, error) {
					return 0, fmt.Errorf("size error")
				},
			},
			expectError: true,
			errorSubstr: "getting image size",
		},
		{
			name: "digest error",
			image: &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return &v1.Manifest{}, nil
				},
				ConfigFileStub: func() (*v1.ConfigFile, error) {
					return &v1.ConfigFile{}, nil
				},
				SizeStub: func() (int64, error) {
					return 1000, nil
				},
				DigestStub: func() (v1.Hash, error) {
					return v1.Hash{}, fmt.Errorf("digest error")
				},
			},
			expectError: true,
			errorSubstr: "getting digest",
		},
		{
			name: "layers error",
			image: &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return &v1.Manifest{}, nil
				},
				ConfigFileStub: func() (*v1.ConfigFile, error) {
					return &v1.ConfigFile{}, nil
				},
				SizeStub: func() (int64, error) {
					return 1000, nil
				},
				DigestStub: func() (v1.Hash, error) {
					return v1.Hash{Algorithm: "sha256", Hex: "abc123"}, nil
				},
				LayersStub: func() ([]v1.Layer, error) {
					return nil, fmt.Errorf("layers error")
				},
			},
			expectError: true,
			errorSubstr: "getting layers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.extractImageInfo(ref, tt.image)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("Expected error containing %q, got %v", tt.errorSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestInsecureTransport(t *testing.T) {
	transport := &insecureTransport{}

	// This is a basic test since the actual implementation just delegates
	// to the default transport. In a real implementation, you'd test
	// that it properly handles insecure connections.
	_ = transport // Use the variable to avoid unused variable warning
}

// Benchmark tests
func BenchmarkNewClient(b *testing.B) {
	opts := ClientOptions{
		UserAgent: "benchmark-agent",
		Insecure:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewClient(opts)
	}
}

func BenchmarkExtractImageInfo(b *testing.B) {
	fakeImage := &fake.FakeImage{
		ConfigFileStub: func() (*v1.ConfigFile, error) {
			return &v1.ConfigFile{
				Architecture: "amd64",
				OS:           "linux",
				Config: v1.Config{
					Labels: map[string]string{"test": "value"},
				},
			}, nil
		},
		SizeStub: func() (int64, error) { return 1000, nil },
		DigestStub: func() (v1.Hash, error) {
			return v1.Hash{Algorithm: "sha256", Hex: "abc123"}, nil
		},
		ManifestStub: func() (*v1.Manifest, error) {
			return &v1.Manifest{}, nil
		},
		LayersStub: func() ([]v1.Layer, error) {
			return []v1.Layer{}, nil
		},
	}

	client := NewClient(ClientOptions{})
	ref, _ := name.ParseReference("nginx:latest")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.extractImageInfo(ref, fakeImage)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestClientOptions(t *testing.T) {
	tests := []struct {
		name string
		opts ClientOptions
	}{
		{
			name: "minimal options",
			opts: ClientOptions{},
		},
		{
			name: "with custom authenticator",
			opts: ClientOptions{
				Authenticator: authn.FromConfig(authn.AuthConfig{
					Username: "testuser",
					Password: "testpass",
				}),
			},
		},
		{
			name: "with all options",
			opts: ClientOptions{
				Authenticator: authn.Anonymous,
				Insecure:      true,
				UserAgent:     "test-agent/1.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.opts)
			if client == nil {
				t.Fatal("NewClient returned nil")
			}

			// Verify client is properly initialized
			if client.options.Authenticator == nil {
				t.Error("Authenticator should never be nil after NewClient")
			}

			if client.options.UserAgent == "" {
				t.Error("UserAgent should never be empty after NewClient")
			}
		})
	}
}

func TestImageConfigValidation(t *testing.T) {
	config := &ImageConfig{
		User:       "testuser",
		WorkingDir: "/app",
		Env:        []string{"PATH=/usr/bin", "HOME=/home/user"},
		Entrypoint: []string{"/entrypoint.sh"},
		Cmd:        []string{"nginx", "-g", "daemon off;"},
		Labels: map[string]string{
			"version":    "1.0",
			"maintainer": "test@example.com",
		},
		ExposedPorts: map[string]struct{}{
			"80/tcp":  {},
			"443/tcp": {},
		},
		Volumes: map[string]struct{}{
			"/data": {},
			"/logs": {},
		},
	}

	// Test that all fields are properly set
	if config.User != "testuser" {
		t.Errorf("Expected User 'testuser', got %q", config.User)
	}

	if config.WorkingDir != "/app" {
		t.Errorf("Expected WorkingDir '/app', got %q", config.WorkingDir)
	}

	if len(config.Env) != 2 {
		t.Errorf("Expected 2 environment variables, got %d", len(config.Env))
	}

	if len(config.Labels) != 2 {
		t.Errorf("Expected 2 labels, got %d", len(config.Labels))
	}

	if len(config.ExposedPorts) != 2 {
		t.Errorf("Expected 2 exposed ports, got %d", len(config.ExposedPorts))
	}

	if len(config.Volumes) != 2 {
		t.Errorf("Expected 2 volumes, got %d", len(config.Volumes))
	}
}

func TestLayerInfoValidation(t *testing.T) {
	layer := LayerInfo{
		Digest:     "sha256:abc123",
		Size:       1024,
		MediaType:  "application/vnd.docker.image.rootfs.diff.tar.gzip",
		CreatedBy:  "RUN apt-get update",
		Comment:    "Update packages",
		EmptyLayer: false,
	}

	if layer.Digest != "sha256:abc123" {
		t.Errorf("Expected digest 'sha256:abc123', got %q", layer.Digest)
	}

	if layer.Size != 1024 {
		t.Errorf("Expected size 1024, got %d", layer.Size)
	}

	if layer.EmptyLayer {
		t.Error("Expected EmptyLayer to be false")
	}

	if layer.CreatedBy != "RUN apt-get update" {
		t.Errorf("Expected CreatedBy 'RUN apt-get update', got %q", layer.CreatedBy)
	}
}

func TestImageInfoValidation(t *testing.T) {
	info := &ImageInfo{
		Registry:     "docker.io",
		Repository:   "library/nginx",
		Tag:          "latest",
		Digest:       "sha256:abc123def456",
		Architecture: "amd64",
		OS:           "linux",
		Size:         1024000,
		Created:      "2023-01-01T00:00:00Z",
		Labels: map[string]string{
			"version": "1.0",
		},
		Layers: []LayerInfo{
			{
				Digest:    "sha256:layer1",
				Size:      512000,
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			},
		},
		Config: &ImageConfig{
			User: "nginx",
		},
	}

	// Validate all fields are accessible and correctly set
	if info.Registry != "docker.io" {
		t.Errorf("Expected registry 'docker.io', got %q", info.Registry)
	}

	if info.Architecture != "amd64" {
		t.Errorf("Expected architecture 'amd64', got %q", info.Architecture)
	}

	if len(info.Layers) != 1 {
		t.Errorf("Expected 1 layer, got %d", len(info.Layers))
	}

	if info.Config == nil {
		t.Fatal("Config should not be nil")
	}

	if info.Config.User != "nginx" {
		t.Errorf("Expected config user 'nginx', got %q", info.Config.User)
	}
}

// Test edge cases for extractImageInfo
func TestExtractImageInfoEdgeCases(t *testing.T) {
	client := NewClient(ClientOptions{})
	ref, _ := name.ParseReference("nginx:latest")

	t.Run("empty config", func(t *testing.T) {
		fakeImage := &fake.FakeImage{
			ConfigFileStub: func() (*v1.ConfigFile, error) {
				return &v1.ConfigFile{}, nil
			},
			SizeStub: func() (int64, error) { return 0, nil },
			DigestStub: func() (v1.Hash, error) {
				return v1.Hash{Algorithm: "sha256", Hex: "empty"}, nil
			},
			ManifestStub: func() (*v1.Manifest, error) {
				return &v1.Manifest{}, nil
			},
			LayersStub: func() ([]v1.Layer, error) {
				return []v1.Layer{}, nil
			},
		}

		info, err := client.extractImageInfo(ref, fakeImage)
		if err != nil {
			t.Fatalf("extractImageInfo failed: %v", err)
		}

		if info.Size != 0 {
			t.Errorf("Expected size 0, got %d", info.Size)
		}

		if len(info.Layers) != 0 {
			t.Errorf("Expected 0 layers, got %d", len(info.Layers))
		}
	})

	t.Run("nil config", func(t *testing.T) {
		fakeImage := &fake.FakeImage{
			ConfigFileStub: func() (*v1.ConfigFile, error) {
				return &v1.ConfigFile{
					Config: v1.Config{}, // Empty config
				}, nil
			},
			SizeStub: func() (int64, error) { return 100, nil },
			DigestStub: func() (v1.Hash, error) {
				return v1.Hash{Algorithm: "sha256", Hex: "nilconfig"}, nil
			},
			ManifestStub: func() (*v1.Manifest, error) {
				return &v1.Manifest{}, nil
			},
			LayersStub: func() ([]v1.Layer, error) {
				return []v1.Layer{}, nil
			},
		}

		info, err := client.extractImageInfo(ref, fakeImage)
		if err != nil {
			t.Fatalf("extractImageInfo failed: %v", err)
		}

		if info.Config == nil {
			t.Error("Config should not be nil")
		}
	})
}
