package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/jhumel-code/artiscanctl/pkg/docker"
	"github.com/jhumel-code/artiscanctl/pkg/scanner"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <command> <target>\n", os.Args[0])
		fmt.Println("Commands:")
		fmt.Println("  scan image <image-ref>    - Scan a Docker image")
		fmt.Println("  scan filesystem <path>    - Scan a filesystem path")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  artiscanctl scan image nginx:latest")
		fmt.Println("  artiscanctl scan filesystem /usr/local")
		os.Exit(1)
	}

	command := os.Args[1]

	ctx := context.Background()

	// Initialize Docker client
	dockerClient := docker.NewClient(docker.ClientOptions{})

	// Use modular scanner manager for comprehensive artifact detection
	scannerManager := scanner.NewModularDefaultManager(dockerClient)

	var err error
	var collection interface{}

	switch command {
	case "scan":
		if len(os.Args) < 4 {
			fmt.Println("Usage: cartographer scan <type> <target>")
			fmt.Println("Types: image, filesystem")
			os.Exit(1)
		}

		scanType := os.Args[2]
		scanTarget := os.Args[3]

		switch scanType {
		case "image":
			collection, err = scannerManager.ScanDockerImage(ctx, scanTarget)
			if err != nil {
				log.Fatalf("Failed to scan image: %v", err)
			}

		case "filesystem":
			collection, err = scannerManager.ScanFilesystem(ctx, scanTarget)
			if err != nil {
				log.Fatalf("Failed to scan filesystem: %v", err)
			}

		default:
			fmt.Printf("Unknown scan type: %s\n", scanType)
			fmt.Println("Supported types: image, filesystem")
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Available commands: scan")
		os.Exit(1)
	}

	// Output results as JSON
	output, err := json.MarshalIndent(collection, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal results: %v", err)
	}

	fmt.Println("\n" + string(output))
}
