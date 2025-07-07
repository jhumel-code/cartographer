package scanner

import (
	"context"
	"io"

	"github.com/jhumel-code/artiscanctl/pkg/artifact"
)

// LayerScanner defines the interface for scanners that can process Docker layer content
type LayerScanner interface {
	artifact.Scanner
	ScanLayer(ctx context.Context, content io.Reader, source artifact.Source) ([]artifact.Artifact, error)
}
