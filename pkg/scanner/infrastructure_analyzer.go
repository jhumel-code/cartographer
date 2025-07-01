package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// InfrastructureAnalyzer scans for Infrastructure as Code files
type InfrastructureAnalyzer struct{}

// NewInfrastructureAnalyzer creates a new infrastructure analyzer
func NewInfrastructureAnalyzer() *InfrastructureAnalyzer {
	return &InfrastructureAnalyzer{}
}

func (i *InfrastructureAnalyzer) Name() string {
	return "infrastructure-analyzer"
}

func (i *InfrastructureAnalyzer) SupportedTypes() []artifact.Type {
	return []artifact.Type{
		artifact.TypeDockerfile,
		artifact.TypeDockerCompose,
		artifact.TypeKubernetesManifest,
		artifact.TypeHelmChart,
		artifact.TypeTerraformConfig,
		artifact.TypeAnsiblePlaybook,
		artifact.TypeVagrantfile,
		artifact.TypeCloudFormation,
		artifact.TypePulumi,
		artifact.TypeAWSCDK,
		artifact.TypeAzureResourceManager,
		artifact.TypeGoogleCloudDeployment,
	}
}

func (i *InfrastructureAnalyzer) Scan(ctx context.Context, source artifact.Source) ([]artifact.Artifact, error) {
	var artifacts []artifact.Artifact

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())
		filePath := strings.ToLower(path)
		relPath, _ := filepath.Rel(source.Location, path)

		var artifactType artifact.Type
		var metadata map[string]string

		switch {
		// Docker
		case fileName == "dockerfile" || strings.HasSuffix(fileName, ".dockerfile"):
			artifactType = artifact.TypeDockerfile
			metadata = map[string]string{
				"iac_type":  "container",
				"platform":  "docker",
				"file_type": "dockerfile",
			}

		case fileName == "docker-compose.yml" || fileName == "docker-compose.yaml" ||
			strings.HasPrefix(fileName, "docker-compose.") && (strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml")):
			artifactType = artifact.TypeDockerCompose
			metadata = map[string]string{
				"iac_type":  "container-orchestration",
				"platform":  "docker-compose",
				"file_type": "yaml",
			}

		// Kubernetes
		case strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml"):
			if i.isKubernetesManifest(path) {
				artifactType = artifact.TypeKubernetesManifest
				metadata = map[string]string{
					"iac_type":  "container-orchestration",
					"platform":  "kubernetes",
					"file_type": "yaml",
				}
			}

		// Helm
		case fileName == "chart.yaml" || fileName == "chart.yml":
			artifactType = artifact.TypeHelmChart
			metadata = map[string]string{
				"iac_type":  "package-manager",
				"platform":  "helm",
				"file_type": "chart-definition",
			}
		case fileName == "values.yaml" || fileName == "values.yml":
			if strings.Contains(filePath, "chart") || strings.Contains(filePath, "helm") {
				artifactType = artifact.TypeHelmChart
				metadata = map[string]string{
					"iac_type":  "package-manager",
					"platform":  "helm",
					"file_type": "values",
				}
			}

		// Terraform
		case strings.HasSuffix(fileName, ".tf"):
			artifactType = artifact.TypeTerraformConfig
			metadata = map[string]string{
				"iac_type":  "provisioning",
				"platform":  "terraform",
				"file_type": "terraform",
			}
		case strings.HasSuffix(fileName, ".tfvars"):
			artifactType = artifact.TypeTerraformConfig
			metadata = map[string]string{
				"iac_type":  "provisioning",
				"platform":  "terraform",
				"file_type": "variables",
			}
		case fileName == "terraform.tf" || fileName == "versions.tf" || fileName == "providers.tf":
			artifactType = artifact.TypeTerraformConfig
			metadata = map[string]string{
				"iac_type":  "provisioning",
				"platform":  "terraform",
				"file_type": "configuration",
			}

		// Ansible
		case strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml"):
			if i.isAnsiblePlaybook(path) {
				artifactType = artifact.TypeAnsiblePlaybook
				metadata = map[string]string{
					"iac_type":  "configuration-management",
					"platform":  "ansible",
					"file_type": "playbook",
				}
			}
		case fileName == "ansible.cfg":
			artifactType = artifact.TypeAnsiblePlaybook
			metadata = map[string]string{
				"iac_type":  "configuration-management",
				"platform":  "ansible",
				"file_type": "configuration",
			}

		// Vagrant
		case fileName == "vagrantfile":
			artifactType = artifact.TypeVagrantfile
			metadata = map[string]string{
				"iac_type":  "virtualization",
				"platform":  "vagrant",
				"file_type": "ruby",
			}

		// AWS CloudFormation
		case strings.HasSuffix(fileName, ".json") || strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml"):
			if i.isCloudFormationTemplate(path) {
				artifactType = artifact.TypeCloudFormation
				metadata = map[string]string{
					"iac_type":  "cloud-provisioning",
					"platform":  "aws-cloudformation",
					"file_type": filepath.Ext(fileName)[1:],
				}
			}

		// AWS CDK
		case strings.HasSuffix(fileName, ".ts") || strings.HasSuffix(fileName, ".js") ||
			strings.HasSuffix(fileName, ".py") || strings.HasSuffix(fileName, ".java"):
			if i.isAWSCDKFile(path) {
				artifactType = artifact.TypeAWSCDK
				metadata = map[string]string{
					"iac_type":  "cloud-provisioning",
					"platform":  "aws-cdk",
					"file_type": filepath.Ext(fileName)[1:],
				}
			}

		// Pulumi
		case strings.HasSuffix(fileName, ".ts") || strings.HasSuffix(fileName, ".js") ||
			strings.HasSuffix(fileName, ".py") || strings.HasSuffix(fileName, ".go"):
			if i.isPulumiProject(path) {
				artifactType = artifact.TypePulumi
				metadata = map[string]string{
					"iac_type":  "cloud-provisioning",
					"platform":  "pulumi",
					"file_type": filepath.Ext(fileName)[1:],
				}
			}
		case fileName == "pulumi.yaml" || fileName == "pulumi.yml":
			artifactType = artifact.TypePulumi
			metadata = map[string]string{
				"iac_type":  "cloud-provisioning",
				"platform":  "pulumi",
				"file_type": "project-config",
			}

		// Azure Resource Manager
		case strings.HasSuffix(fileName, ".json"):
			if i.isAzureARMTemplate(path) {
				artifactType = artifact.TypeAzureResourceManager
				metadata = map[string]string{
					"iac_type":  "cloud-provisioning",
					"platform":  "azure-arm",
					"file_type": "json",
				}
			}

		// Google Cloud Deployment Manager
		case strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml"):
			if i.isGoogleCloudDeployment(path) {
				artifactType = artifact.TypeGoogleCloudDeployment
				metadata = map[string]string{
					"iac_type":  "cloud-provisioning",
					"platform":  "google-cloud-deployment",
					"file_type": "yaml",
				}
			}
		}

		if artifactType != "" {
			modTime := info.ModTime()
			artifact := artifact.Artifact{
				Name:        info.Name(),
				Type:        artifactType,
				Path:        relPath,
				Source:      source,
				Size:        info.Size(),
				Permissions: info.Mode().String(),
				ModTime:     &modTime,
				Metadata:    metadata,
			}
			artifacts = append(artifacts, artifact)
		}

		return nil
	})

	return artifacts, err
}

func (i *InfrastructureAnalyzer) isKubernetesManifest(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for Kubernetes API version and kind
	return strings.Contains(contentStr, "apiVersion:") && strings.Contains(contentStr, "kind:")
}

func (i *InfrastructureAnalyzer) isAnsiblePlaybook(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for Ansible playbook indicators
	return strings.Contains(contentStr, "hosts:") &&
		(strings.Contains(contentStr, "tasks:") || strings.Contains(contentStr, "roles:"))
}

func (i *InfrastructureAnalyzer) isCloudFormationTemplate(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for CloudFormation template indicators
	return strings.Contains(contentStr, "AWSTemplateFormatVersion") ||
		(strings.Contains(contentStr, "Resources:") && strings.Contains(contentStr, "Type:"))
}

func (i *InfrastructureAnalyzer) isAWSCDKFile(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for AWS CDK imports and constructs
	return strings.Contains(contentStr, "@aws-cdk/") ||
		strings.Contains(contentStr, "aws-cdk-lib") ||
		strings.Contains(contentStr, "import * as cdk") ||
		strings.Contains(contentStr, "from aws_cdk")
}

func (i *InfrastructureAnalyzer) isPulumiProject(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for Pulumi imports
	return strings.Contains(contentStr, "import * as pulumi") ||
		strings.Contains(contentStr, "from pulumi") ||
		strings.Contains(contentStr, "\"@pulumi/")
}

func (i *InfrastructureAnalyzer) isAzureARMTemplate(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for Azure ARM template indicators
	return strings.Contains(contentStr, "\"$schema\"") &&
		strings.Contains(contentStr, "deploymentTemplate") &&
		strings.Contains(contentStr, "\"resources\":")
}

func (i *InfrastructureAnalyzer) isGoogleCloudDeployment(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	contentStr := string(content)
	// Look for Google Cloud Deployment Manager indicators
	return strings.Contains(contentStr, "type: compute.v1.instance") ||
		strings.Contains(contentStr, "type: storage.v1.bucket") ||
		(strings.Contains(contentStr, "imports:") && strings.Contains(contentStr, ".jinja"))
}
