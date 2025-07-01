package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Client provides Docker image operations using go-containerregistry
type Client struct {
	options ClientOptions
}

// ClientOptions configures the Docker client
type ClientOptions struct {
	// Authenticator for registry authentication
	Authenticator authn.Authenticator

	// Insecure allows insecure registry connections
	Insecure bool

	// UserAgent sets the user agent for requests
	UserAgent string
}

// NewClient creates a new Docker client
func NewClient(opts ClientOptions) *Client {
	if opts.Authenticator == nil {
		opts.Authenticator = authn.Anonymous
	}

	if opts.UserAgent == "" {
		opts.UserAgent = "cartographer/1.0"
	}

	return &Client{
		options: opts,
	}
}

// ImageInfo contains metadata about a Docker image
type ImageInfo struct {
	// Registry and repository information
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`

	// Image metadata
	Architecture string            `json:"architecture"`
	OS           string            `json:"os"`
	Size         int64             `json:"size"`
	Created      string            `json:"created"`
	Labels       map[string]string `json:"labels"`

	// Layer information
	Layers []LayerInfo `json:"layers"`

	// Configuration
	Config *ImageConfig `json:"config,omitempty"`
}

// LayerInfo contains information about an image layer
type LayerInfo struct {
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	MediaType  string `json:"media_type"`
	CreatedBy  string `json:"created_by,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"empty_layer"`
}

// ImageConfig contains image configuration details
type ImageConfig struct {
	User         string              `json:"user,omitempty"`
	ExposedPorts map[string]struct{} `json:"exposed_ports,omitempty"`
	Env          []string            `json:"env,omitempty"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	Cmd          []string            `json:"cmd,omitempty"`
	Volumes      map[string]struct{} `json:"volumes,omitempty"`
	WorkingDir   string              `json:"working_dir,omitempty"`
	Labels       map[string]string   `json:"labels,omitempty"`
}

// PullImage pulls a Docker image and returns image information
func (c *Client) PullImage(ctx context.Context, imageRef string) (*ImageInfo, v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing image reference: %w", err)
	}

	options := []remote.Option{
		remote.WithAuth(c.options.Authenticator),
		remote.WithUserAgent(c.options.UserAgent),
	}

	if c.options.Insecure {
		options = append(options, remote.WithTransport(&insecureTransport{}))
	}

	img, err := remote.Image(ref, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("pulling image: %w", err)
	}

	info, err := c.extractImageInfo(ref, img)
	if err != nil {
		return nil, nil, fmt.Errorf("extracting image info: %w", err)
	}

	return info, img, nil
}

// LoadImageFromTar loads a Docker image from a tar file
func (c *Client) LoadImageFromTar(ctx context.Context, tarPath string) (*ImageInfo, v1.Image, error) {
	img, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("loading image from tar: %w", err)
	}

	// Create a dummy reference for tar-loaded images
	ref, err := name.ParseReference("localhost/loaded-image:latest")
	if err != nil {
		return nil, nil, fmt.Errorf("creating reference for tar image: %w", err)
	}

	info, err := c.extractImageInfo(ref, img)
	if err != nil {
		return nil, nil, fmt.Errorf("extracting image info: %w", err)
	}

	return info, img, nil
}

// GetLayerContent returns the content of a specific layer
func (c *Client) GetLayerContent(layer v1.Layer) (io.ReadCloser, error) {
	return layer.Uncompressed()
}

// extractImageInfo extracts metadata from a v1.Image
func (c *Client) extractImageInfo(ref name.Reference, img v1.Image) (*ImageInfo, error) {
	_, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("getting manifest: %w", err)
	}

	config, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("getting config: %w", err)
	}

	size, err := img.Size()
	if err != nil {
		return nil, fmt.Errorf("getting image size: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("getting digest: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting layers: %w", err)
	}

	// Extract layer information
	layerInfos := make([]LayerInfo, len(layers))
	for i, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("getting layer digest: %w", err)
		}

		layerSize, err := layer.Size()
		if err != nil {
			return nil, fmt.Errorf("getting layer size: %w", err)
		}

		mediaType, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("getting layer media type: %w", err)
		}

		layerInfo := LayerInfo{
			Digest:    layerDigest.String(),
			Size:      layerSize,
			MediaType: string(mediaType),
		}

		// Add history information if available
		if i < len(config.History) {
			history := config.History[i]
			layerInfo.CreatedBy = history.CreatedBy
			layerInfo.Comment = history.Comment
			layerInfo.EmptyLayer = history.EmptyLayer
		}

		layerInfos[i] = layerInfo
	}

	imageConfig := &ImageConfig{
		User:         config.Config.User,
		ExposedPorts: config.Config.ExposedPorts,
		Env:          config.Config.Env,
		Entrypoint:   config.Config.Entrypoint,
		Cmd:          config.Config.Cmd,
		Volumes:      config.Config.Volumes,
		WorkingDir:   config.Config.WorkingDir,
		Labels:       config.Config.Labels,
	}

	return &ImageInfo{
		Registry:     ref.Context().RegistryStr(),
		Repository:   ref.Context().RepositoryStr(),
		Tag:          getTag(ref),
		Digest:       digest.String(),
		Architecture: config.Architecture,
		OS:           config.OS,
		Size:         size,
		Created:      config.Created.String(),
		Labels:       config.Config.Labels,
		Layers:       layerInfos,
		Config:       imageConfig,
	}, nil
}

// getTag extracts the tag from a reference
func getTag(ref name.Reference) string {
	if tagged, ok := ref.(name.Tag); ok {
		return tagged.TagStr()
	}
	return ""
}

// insecureTransport allows insecure registry connections
type insecureTransport struct{}

func (t *insecureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// This is a placeholder - in a real implementation, you'd configure
	// an HTTP transport that allows insecure connections
	return http.DefaultTransport.RoundTrip(req)
}
