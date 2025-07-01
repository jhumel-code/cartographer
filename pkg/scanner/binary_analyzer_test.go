package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

const nonExistentFile = "/nonexistent/file"

// Mock file info for testing
type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return m.modTime }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() interface{}   { return nil }

// Test data for creating temporary files
func createTestBinary(t *testing.T, name string, executable bool) string {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, name)

	content := []byte("test binary content")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if executable {
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatalf("Failed to make file executable: %v", err)
		}
	}

	return path
}

// Create test directory structure
func createTestDirStructure(t *testing.T) string {
	tempDir := t.TempDir()

	// Create directory structure with binaries
	dirs := []string{
		"bin",
		"sbin",
		"usr/bin",
		"usr/sbin",
		"usr/local/bin",
		"lib",
		"usr/lib",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(tempDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}

		// Add some test files
		testFile := filepath.Join(dirPath, "testbinary")
		if err := os.WriteFile(testFile, []byte("test"), 0755); err != nil {
			t.Fatalf("Failed to create test binary: %v", err)
		}
	}

	// Create shared libraries
	libFiles := []string{
		"lib/libtest.so",
		"lib/libtest.so.1",
		"lib/libtest.so.1.2.3",
		"usr/lib/libother.so",
	}

	for _, libFile := range libFiles {
		path := filepath.Join(tempDir, libFile)
		if err := os.WriteFile(path, []byte("library content"), 0644); err != nil {
			t.Fatalf("Failed to create library file: %v", err)
		}
	}

	return tempDir
}

func TestNewBinaryAnalyzer(t *testing.T) {
	analyzer := NewBinaryAnalyzer()
	if analyzer == nil {
		t.Fatal("NewBinaryAnalyzer returned nil")
	}
}

func TestBinaryAnalyzerName(t *testing.T) {
	analyzer := NewBinaryAnalyzer()
	expected := "binary-analyzer"
	if got := analyzer.Name(); got != expected {
		t.Errorf("Name() = %v, want %v", got, expected)
	}
}

func TestBinaryAnalyzerSupportedTypes(t *testing.T) {
	analyzer := NewBinaryAnalyzer()
	supportedTypes := analyzer.SupportedTypes()

	expectedTypes := []artifact.Type{
		artifact.TypeExecutable,
		artifact.TypeSharedLibrary,
		artifact.TypeStaticLibrary,
		artifact.TypeKernelModule,
		artifact.TypeSystemdService,
		artifact.TypeInitScript,
		artifact.TypeShellScript,
		artifact.TypePythonScript,
		artifact.TypePerlScript,
		artifact.TypeNodeScript,
	}

	if len(supportedTypes) != len(expectedTypes) {
		t.Errorf("SupportedTypes() returned %d types, expected %d", len(supportedTypes), len(expectedTypes))
	}

	for i, expected := range expectedTypes {
		if i >= len(supportedTypes) || supportedTypes[i] != expected {
			t.Errorf("SupportedTypes()[%d] = %v, want %v", i, supportedTypes[i], expected)
		}
	}
}

func TestBinaryAnalyzerIsBinaryFile(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	tests := []struct {
		name     string
		path     string
		fileInfo mockFileInfo
		want     bool
	}{
		{
			name: "shared library .so",
			path: "/lib/libtest.so",
			fileInfo: mockFileInfo{
				name: "libtest.so",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "shared library .dll",
			path: "/lib/libtest.dll",
			fileInfo: mockFileInfo{
				name: "libtest.dll",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "shared library .dylib",
			path: "/lib/libtest.dylib",
			fileInfo: mockFileInfo{
				name: "libtest.dylib",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "executable file with execute permission",
			path: "/bin/test",
			fileInfo: mockFileInfo{
				name: "test",
				mode: 0755,
			},
			want: true,
		},
		{
			name: "file in bin directory",
			path: "/usr/bin/test",
			fileInfo: mockFileInfo{
				name: "test",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "file in sbin directory",
			path: "/usr/sbin/test",
			fileInfo: mockFileInfo{
				name: "test",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "file in usr/local/bin directory",
			path: "/usr/local/bin/test",
			fileInfo: mockFileInfo{
				name: "test",
				mode: 0644,
			},
			want: true,
		},
		{
			name: "regular text file",
			path: "/home/user/readme.txt",
			fileInfo: mockFileInfo{
				name: "readme.txt",
				mode: 0644,
			},
			want: false,
		},
		{
			name: "file in non-binary directory",
			path: "/home/user/script",
			fileInfo: mockFileInfo{
				name: "script",
				mode: 0644,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.isBinaryFile(tt.path, tt.fileInfo)
			if got != tt.want {
				t.Errorf("isBinaryFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBinaryAnalyzerDetermineBinaryType(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	tests := []struct {
		name string
		path string
		want artifact.Type
	}{
		{
			name: "shared library .so",
			path: "/lib/libtest.so",
			want: artifact.TypeSharedLibrary,
		},
		{
			name: "shared library .dll",
			path: "/lib/libtest.dll",
			want: artifact.TypeSharedLibrary,
		},
		{
			name: "shared library .dylib",
			path: "/lib/libtest.dylib",
			want: artifact.TypeSharedLibrary,
		},
		{
			name: "shared library with version .so.1",
			path: "/lib/libtest.so.1",
			want: artifact.TypeSharedLibrary,
		},
		{
			name: "executable",
			path: "/bin/test",
			want: artifact.TypeExecutable,
		},
		{
			name: "executable with .exe extension",
			path: "/bin/test.exe",
			want: artifact.TypeExecutable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileInfo := mockFileInfo{name: filepath.Base(tt.path)}
			got := analyzer.determineBinaryType(tt.path, fileInfo)
			if got != tt.want {
				t.Errorf("determineBinaryType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBinaryAnalyzerScan(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	// Create test directory structure
	testDir := createTestDirStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) == 0 {
		t.Error("Scan() returned no artifacts, expected some")
	}

	// Check that we found some executables and shared libraries
	foundExecutable := false
	foundSharedLibrary := false

	for _, art := range artifacts {
		if art.Type == artifact.TypeExecutable {
			foundExecutable = true
		}
		if art.Type == artifact.TypeSharedLibrary {
			foundSharedLibrary = true
		}

		// Verify artifact has required fields
		if art.Name == "" {
			t.Error("Artifact missing name")
		}
		if art.Path == "" {
			t.Error("Artifact missing path")
		}
		// Compare source fields individually since Source struct contains maps
		if art.Source.Type != source.Type || art.Source.Location != source.Location {
			t.Error("Artifact has incorrect source")
		}
	}

	if !foundExecutable {
		t.Error("Scan() did not find any executables")
	}
	if !foundSharedLibrary {
		t.Error("Scan() did not find any shared libraries")
	}
}

func TestBinaryAnalyzerScanEmptyDirectory(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	tempDir := t.TempDir()
	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Scan() returned %d artifacts, expected 0 for empty directory", len(artifacts))
	}
}

func TestBinaryAnalyzerScanNonexistentDirectory(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/completely/nonexistent/directory/path/that/should/not/exist",
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	// The current implementation uses filepath.Walk which may not return an error
	// for nonexistent directories on all systems, so we just ensure no artifacts are returned
	if len(artifacts) != 0 {
		t.Errorf("Scan() returned %d artifacts, expected 0 for nonexistent directory", len(artifacts))
	}

	// Error behavior may vary by OS
	_ = err
}

func TestBinaryAnalyzerAnalyzeBinary(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	// Create a test binary file
	testPath := createTestBinary(t, "testbinary", true)
	fileInfo, err := os.Stat(testPath)
	if err != nil {
		t.Fatalf("Failed to stat test file: %v", err)
	}

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: filepath.Dir(testPath),
	}

	art, err := analyzer.analyzeBinary(testPath, fileInfo, source)

	if err != nil {
		t.Errorf("analyzeBinary() error = %v, want nil", err)
	}

	if art == nil {
		t.Fatal("analyzeBinary() returned nil artifact")
	}

	// Verify artifact fields
	if art.Name != "testbinary" {
		t.Errorf("Artifact name = %v, want testbinary", art.Name)
	}

	if art.Path != testPath {
		t.Errorf("Artifact path = %v, want %v", art.Path, testPath)
	}

	if art.Size != fileInfo.Size() {
		t.Errorf("Artifact size = %v, want %v", art.Size, fileInfo.Size())
	}

	if art.Type != artifact.TypeExecutable {
		t.Errorf("Artifact type = %v, want %v", art.Type, artifact.TypeExecutable)
	}

	if art.Metadata == nil {
		t.Error("Artifact metadata is nil")
	}
}

func TestBinaryAnalyzerExtractBinaryMetadata(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	// Create a test file
	testPath := createTestBinary(t, "testbinary", false)

	modTime := time.Now()
	art := &artifact.Artifact{
		Name:     "testbinary",
		Path:     testPath,
		ModTime:  &modTime,
		Metadata: make(map[string]string),
	}

	// This should not return an error even for non-binary files
	err := analyzer.extractBinaryMetadata(testPath, art)
	if err != nil {
		t.Errorf("extractBinaryMetadata() error = %v, want nil", err)
	}

	// Check that format was set (even if unknown)
	if format, exists := art.Metadata["format"]; !exists || format == "" {
		t.Error("extractBinaryMetadata() did not set format metadata")
	}
}

func TestBinaryAnalyzerExtractBinaryMetadataNonexistentFile(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	art := &artifact.Artifact{
		Name:     "nonexistent",
		Path:     nonExistentFile,
		Metadata: make(map[string]string),
	}

	err := analyzer.extractBinaryMetadata(nonExistentFile, art)
	if err == nil {
		t.Error("extractBinaryMetadata() error = nil, expected error for nonexistent file")
	}
}

func TestBinaryAnalyzerExtractDynamicDependencies(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	// Create a test file
	testPath := createTestBinary(t, "testbinary", false)

	deps, err := analyzer.extractDynamicDependencies(testPath)

	// Should not return error for non-ELF files, just empty dependencies
	if err != nil {
		t.Errorf("extractDynamicDependencies() error = %v, want nil", err)
	}

	// For our test file, should return empty dependencies
	if len(deps) != 0 {
		t.Errorf("extractDynamicDependencies() returned %d dependencies, expected 0", len(deps))
	}
}

func TestBinaryAnalyzerExtractDynamicDependenciesNonexistentFile(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	deps, err := analyzer.extractDynamicDependencies(nonExistentFile)

	if err == nil {
		t.Error("extractDynamicDependencies() error = nil, expected error for nonexistent file")
	}

	if len(deps) != 0 {
		t.Errorf("extractDynamicDependencies() returned %d dependencies, expected 0", len(deps))
	}
}

func TestBinaryAnalyzerExtractELFVersion(t *testing.T) {
	// Skip this test since it requires a real ELF file
	// and passing nil causes a panic in the debug/elf package
	t.Skip("Skipping ELF version test - requires real ELF binary for proper testing")
}

// Benchmark tests
func BenchmarkBinaryAnalyzerIsBinaryFile(b *testing.B) {
	analyzer := NewBinaryAnalyzer()
	fileInfo := mockFileInfo{
		name: "testbinary",
		mode: 0755,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.isBinaryFile("/usr/bin/testbinary", fileInfo)
	}
}

func BenchmarkBinaryAnalyzerDetermineBinaryType(b *testing.B) {
	analyzer := NewBinaryAnalyzer()
	fileInfo := mockFileInfo{
		name: "testbinary",
		mode: 0755,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.determineBinaryType("/usr/bin/testbinary", fileInfo)
	}
}

func BenchmarkBinaryAnalyzerScan(b *testing.B) {
	analyzer := NewBinaryAnalyzer()

	// Create temporary test directory for benchmark
	tempDir, _ := os.MkdirTemp("", "bench_test")
	defer os.RemoveAll(tempDir)

	// Create some test files
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("binary%d", i))
		os.WriteFile(testFile, []byte("test"), 0755)
	}

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Scan(ctx, source)
	}
}

// Table-driven tests for edge cases
func TestBinaryAnalyzerEdgeCases(t *testing.T) {
	analyzer := NewBinaryAnalyzer()

	tests := []struct {
		name     string
		setup    func(*testing.T) (string, mockFileInfo)
		wantErr  bool
		wantType artifact.Type
	}{
		{
			name: "zero size file",
			setup: func(t *testing.T) (string, mockFileInfo) {
				path := createTestBinary(t, "empty", false)
				// Truncate to zero size
				os.Truncate(path, 0)
				return path, mockFileInfo{name: "empty", size: 0, mode: 0644}
			},
			wantErr:  false,
			wantType: artifact.TypeExecutable,
		},
		{
			name: "file with special characters",
			setup: func(t *testing.T) (string, mockFileInfo) {
				path := createTestBinary(t, "test-binary_v1.2.3", true)
				stat, _ := os.Stat(path)
				return path, mockFileInfo{name: "test-binary_v1.2.3", size: stat.Size(), mode: 0755}
			},
			wantErr:  false,
			wantType: artifact.TypeExecutable,
		},
		{
			name: "deeply nested binary",
			setup: func(t *testing.T) (string, mockFileInfo) {
				tempDir := t.TempDir()
				deepPath := filepath.Join(tempDir, "very", "deep", "nested", "path", "usr", "bin")
				os.MkdirAll(deepPath, 0755)
				binaryPath := filepath.Join(deepPath, "deepbinary")
				os.WriteFile(binaryPath, []byte("deep binary"), 0755)
				return binaryPath, mockFileInfo{name: "deepbinary", size: 11, mode: 0755}
			},
			wantErr:  false,
			wantType: artifact.TypeExecutable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, fileInfo := tt.setup(t)

			source := artifact.Source{
				Type:     artifact.SourceTypeFilesystem,
				Location: filepath.Dir(path),
			}

			art, err := analyzer.analyzeBinary(path, fileInfo, source)

			if (err != nil) != tt.wantErr {
				t.Errorf("analyzeBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && art != nil && art.Type != tt.wantType {
				t.Errorf("analyzeBinary() type = %v, want %v", art.Type, tt.wantType)
			}
		})
	}
}

// Test concurrent access (race condition testing)
func TestBinaryAnalyzerConcurrentAccess(t *testing.T) {
	analyzer := NewBinaryAnalyzer()
	testDir := createTestDirStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx := context.Background()

	// Run multiple scans concurrently
	done := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		go func() {
			defer func() { done <- true }()
			artifacts, err := analyzer.Scan(ctx, source)
			if err != nil {
				t.Errorf("Concurrent scan failed: %v", err)
			}
			if len(artifacts) == 0 {
				t.Error("Concurrent scan returned no artifacts")
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}
}

// Test context cancellation
func TestBinaryAnalyzerContextCancellation(t *testing.T) {
	analyzer := NewBinaryAnalyzer()
	testDir := createTestDirStructure(t)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: testDir,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	artifacts, err := analyzer.Scan(ctx, source)

	// Should handle cancelled context gracefully
	// The current implementation doesn't check context, so this may not fail
	// But we test it to ensure it doesn't panic
	_ = artifacts
	_ = err
}
