package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ianjhumelbautista/cartographer/pkg/artifact"
)

// Test constants to avoid duplication
const (
	// File names
	infraDockerfileFile         = "Dockerfile"
	infraDockerComposeFile      = "docker-compose.yml"
	infraKubernetesManifestFile = "deployment.yaml"
	infraHelmChartFile          = "Chart.yaml"
	infraHelmValuesFile         = "values.yaml"
	infraTerraformFile          = "main.tf"
	infraTerraformVarsFile      = "terraform.tfvars"
	infraAnsiblePlaybookFile    = "playbook.yml"
	infraAnsibleConfigFile      = "ansible.cfg"
	infraVagrantFile            = "Vagrantfile"
	infraCloudFormationFile     = "template.json"
	infraAwsCdkFile             = "app.ts"
	infraPulumiFile             = "index.ts"
	infraPulumiConfigFile       = "Pulumi.yaml"
	infraAzureArmFile           = "template.json"
	infraGoogleCloudDeployFile  = "deployment.yaml"

	// Error messages
	infraScanErrorMsg        = "Scan() error = %v"
	infraExpectedArtifactMsg = "Expected to find artifact with name '%s'"
	infraExpectedTypeMsg     = "Expected artifact type '%s', got '%s'"
	infraExpectedMetadataMsg = "Expected metadata '%s' to be '%s', got '%s'"

	// Dockerfile content
	dockerfileContent = `FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]`

	// Docker Compose content
	dockerComposeContent = `version: '3.8'

services:
  web:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
  
  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=myapp
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:`

	// Kubernetes manifest content
	kubernetesManifestContent = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80`

	// Helm Chart.yaml content
	helmChartContent = `apiVersion: v2
name: my-app
description: A Helm chart for my application
type: application
version: 0.1.0
appVersion: "1.16.0"

dependencies:
- name: postgresql
  version: 11.6.12
  repository: https://charts.bitnami.com/bitnami`

	// Helm values.yaml content
	helmValuesContent = `replicaCount: 1

image:
  repository: nginx
  pullPolicy: IfNotPresent
  tag: ""

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: false
  className: ""
  annotations: {}
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: ImplementationSpecific`

	// Terraform main.tf content
	infraTerraformContent = `terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "main-vpc"
  }
}`

	// Terraform variables content
	terraformVarsContent = `aws_region = "us-west-2"
vpc_cidr   = "10.0.0.0/16"
environment = "production"
project_name = "my-project"`

	// Ansible playbook content
	ansiblePlaybookContent = `---
- name: Deploy web application
  hosts: webservers
  become: yes
  vars:
    app_name: myapp
    app_port: 8080

  tasks:
    - name: Install required packages
      package:
        name:
          - nginx
          - python3
        state: present

    - name: Start and enable nginx
      service:
        name: nginx
        state: started
        enabled: yes

  roles:
    - common
    - webserver`

	// Ansible configuration content
	ansibleConfigContent = `[defaults]
inventory = ./inventory
remote_user = ubuntu
private_key_file = ~/.ssh/id_rsa
host_key_checking = False
retry_files_enabled = False

[privilege_escalation]
become = True
become_method = sudo
become_user = root
become_ask_pass = False`

	// Vagrantfile content
	vagrantFileContent = `Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.hostname = "dev-machine"
  
  config.vm.network "private_network", ip: "192.168.33.10"
  config.vm.network "forwarded_port", guest: 80, host: 8080
  
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end
  
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y nginx
    systemctl enable nginx
    systemctl start nginx
  SHELL
end`

	// CloudFormation template content
	cloudFormationContent = `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "CloudFormation template for EC2 instance",
  "Parameters": {
    "InstanceType": {
      "Type": "String",
      "Default": "t3.micro",
      "Description": "EC2 instance type"
    }
  },
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": { "Ref": "InstanceType" },
        "ImageId": "ami-0abcdef1234567890",
        "SecurityGroups": [
          { "Ref": "MySecurityGroup" }
        ]
      }
    },
    "MySecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Security group for EC2 instance",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ]
      }
    }
  }
}`

	// AWS CDK TypeScript content
	awsCdkContent = `import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import { Construct } from 'constructs';

export class MyStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create VPC
    const vpc = new ec2.Vpc(this, 'MyVpc', {
      maxAzs: 2,
      natGateways: 1,
    });

    // Create ECS Cluster
    const cluster = new ecs.Cluster(this, 'MyCluster', {
      vpc: vpc,
      containerInsights: true,
    });

    // Create Fargate task definition
    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDef', {
      memoryLimitMiB: 512,
      cpu: 256,
    });

    taskDefinition.addContainer('web', {
      image: ecs.ContainerImage.fromRegistry('nginx'),
      portMappings: [{ containerPort: 80 }],
    });
  }
}`

	// Pulumi TypeScript content
	pulumiContent = `import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const vpc = new aws.ec2.Vpc("main", {
    cidrBlock: "10.0.0.0/16",
    enableDnsHostnames: true,
    enableDnsSupport: true,
    tags: {
        Name: "main-vpc",
    },
});

const internetGateway = new aws.ec2.InternetGateway("main", {
    vpcId: vpc.id,
    tags: {
        Name: "main-igw",
    },
});

const subnet = new aws.ec2.Subnet("main", {
    vpcId: vpc.id,
    cidrBlock: "10.0.1.0/24",
    availabilityZone: "us-west-2a",
    mapPublicIpOnLaunch: true,
    tags: {
        Name: "main-subnet",
    },
});

export const vpcId = vpc.id;
export const subnetId = subnet.id;`

	// Pulumi project configuration
	pulumiConfigContent = `name: my-pulumi-project
runtime: nodejs
description: A simple Pulumi program for AWS infrastructure

config:
  aws:region: us-west-2

template:
  description: AWS TypeScript template
  quickstart: aws-typescript`

	// Azure ARM template content
	azureArmContent = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmName": {
      "type": "string",
      "defaultValue": "myVM",
      "metadata": {
        "description": "Name of the virtual machine"
      }
    },
    "adminUsername": {
      "type": "string",
      "metadata": {
        "description": "Admin username for the VM"
      }
    }
  },
  "variables": {
    "storageAccountName": "[concat('storage', uniqueString(resourceGroup().id))]"
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-04-01",
      "name": "[variables('storageAccountName')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "Standard_LRS"
      },
      "kind": "StorageV2"
    }
  ]
}`

	// Google Cloud Deployment Manager content
	googleCloudDeployContent = `imports:
- name: vm-template.jinja
  path: vm-template.jinja

resources:
- name: my-vm
  type: compute.v1.instance
  properties:
    zone: us-central1-a
    machineType: projects/PROJECT_ID/zones/us-central1-a/machineTypes/n1-standard-1
    disks:
    - deviceName: boot
      type: PERSISTENT
      boot: true
      autoDelete: true
      initializeParams:
        sourceImage: projects/debian-cloud/global/images/family/debian-11
    networkInterfaces:
    - network: projects/PROJECT_ID/global/networks/default
      accessConfigs:
      - name: External NAT
        type: ONE_TO_ONE_NAT

- name: my-bucket
  type: storage.v1.bucket
  properties:
    location: US
    storageClass: STANDARD`

	// Non-infrastructure YAML content (should not be detected as K8s)
	regularYamlContent = `database:
  host: localhost
  port: 5432
  name: myapp
  user: postgres

logging:
  level: info
  file: /var/log/app.log

features:
  feature1: true
  feature2: false`

	// Non-CloudFormation JSON content
	regularJsonContent = `{
  "name": "my-app",
  "version": "1.0.0",
  "description": "A sample application",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}`
)

// Helper function to create test files for infrastructure analyzer
func createInfraTestFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)

	// Create subdirectories if needed
	if subdir := filepath.Dir(path); subdir != dir {
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", subdir, err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file %s: %v", path, err)
	}

	return path
}

func TestNewInfrastructureAnalyzer(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	if analyzer == nil {
		t.Error("NewInfrastructureAnalyzer() returned nil")
	}
}

func TestInfrastructureAnalyzerName(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	name := analyzer.Name()
	if name != "infrastructure-analyzer" {
		t.Errorf("Expected name 'infrastructure-analyzer', got '%s'", name)
	}
}

func TestInfrastructureAnalyzerSupportedTypes(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	types := analyzer.SupportedTypes()

	expectedTypes := []artifact.Type{
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

	if len(types) != len(expectedTypes) {
		t.Errorf("Expected %d supported types, got %d", len(expectedTypes), len(types))
	}

	// Create a map for easier checking
	typeMap := make(map[artifact.Type]bool)
	for _, t := range types {
		typeMap[t] = true
	}

	for _, expectedType := range expectedTypes {
		if !typeMap[expectedType] {
			t.Errorf("Expected type %v not found in supported types", expectedType)
		}
	}
}

func TestInfrastructureAnalyzerScan(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Create test files for different infrastructure types
	createInfraTestFile(t, tempDir, infraDockerfileFile, dockerfileContent)
	createInfraTestFile(t, tempDir, infraDockerComposeFile, dockerComposeContent)
	createInfraTestFile(t, tempDir, infraKubernetesManifestFile, kubernetesManifestContent)
	createInfraTestFile(t, tempDir, infraTerraformFile, infraTerraformContent)
	createInfraTestFile(t, tempDir, infraVagrantFile, vagrantFileContent)
	createInfraTestFile(t, tempDir, infraCloudFormationFile, cloudFormationContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, want nil", err)
		return
	}

	if len(artifacts) == 0 {
		t.Error("Expected artifacts to be found, got none")
		return
	}

	// Check that we found different infrastructure types
	foundTypes := make(map[artifact.Type]bool)
	foundNames := make(map[string]bool)
	for _, art := range artifacts {
		foundTypes[art.Type] = true
		foundNames[art.Name] = true
	}

	// Check for the main types that should be detected
	expectedArtifacts := map[string]artifact.Type{
		infraDockerfileFile:         artifact.TypeDockerfile,
		infraDockerComposeFile:      artifact.TypeDockerCompose,
		infraKubernetesManifestFile: artifact.TypeKubernetesManifest,
		infraTerraformFile:          artifact.TypeTerraformConfig,
		infraVagrantFile:            artifact.TypeVagrantfile,
		infraCloudFormationFile:     artifact.TypeCloudFormation,
	}

	for name, expectedType := range expectedArtifacts {
		if !foundNames[name] {
			t.Errorf("Expected to find artifact with name '%s'", name)
		}
		if !foundTypes[expectedType] {
			t.Errorf("Expected to find artifact of type %v", expectedType)
		}
	}
}

// Test Docker-specific files
func TestInfrastructureAnalyzerDockerfile(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, infraDockerfileFile, dockerfileContent)
	createInfraTestFile(t, tempDir, "production.dockerfile", dockerfileContent)
	createInfraTestFile(t, tempDir, "backend.dockerfile", dockerfileContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	dockerfileCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeDockerfile {
			dockerfileCount++

			// Check metadata
			if art.Metadata["iac_type"] != "container" {
				t.Errorf("Expected iac_type 'container', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "docker" {
				t.Errorf("Expected platform 'docker', got '%s'", art.Metadata["platform"])
			}
			if art.Metadata["file_type"] != "dockerfile" {
				t.Errorf("Expected file_type 'dockerfile', got '%s'", art.Metadata["file_type"])
			}
		}
	}

	if dockerfileCount != 3 {
		t.Errorf("Expected 3 Dockerfile artifacts, got %d", dockerfileCount)
	}
}

func TestInfrastructureAnalyzerDockerCompose(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "docker-compose.yml", dockerComposeContent)
	createInfraTestFile(t, tempDir, "docker-compose.yaml", dockerComposeContent)
	createInfraTestFile(t, tempDir, "docker-compose.prod.yml", dockerComposeContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	composeCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeDockerCompose {
			composeCount++

			// Check metadata
			if art.Metadata["iac_type"] != "container-orchestration" {
				t.Errorf("Expected iac_type 'container-orchestration', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "docker-compose" {
				t.Errorf("Expected platform 'docker-compose', got '%s'", art.Metadata["platform"])
			}
		}
	}

	if composeCount != 3 {
		t.Errorf("Expected 3 Docker Compose artifacts, got %d", composeCount)
	}
}

// Test Kubernetes files
func TestInfrastructureAnalyzerKubernetes(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "deployment.yaml", kubernetesManifestContent)
	createInfraTestFile(t, tempDir, "service.yml", kubernetesManifestContent)
	createInfraTestFile(t, tempDir, "regular-config.yaml", regularYamlContent) // Should not be detected

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	k8sCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeKubernetesManifest {
			k8sCount++

			// Check metadata
			if art.Metadata["iac_type"] != "container-orchestration" {
				t.Errorf("Expected iac_type 'container-orchestration', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "kubernetes" {
				t.Errorf("Expected platform 'kubernetes', got '%s'", art.Metadata["platform"])
			}
		}
	}

	// Should only detect the 2 K8s manifests, not the regular YAML
	if k8sCount != 2 {
		t.Errorf("Expected 2 Kubernetes artifacts, got %d", k8sCount)
	}
}

// Test Helm files
func TestInfrastructureAnalyzerHelm(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Create Helm chart structure
	createInfraTestFile(t, tempDir, "charts/mychart/Chart.yaml", helmChartContent)
	createInfraTestFile(t, tempDir, "charts/mychart/values.yaml", helmValuesContent)
	createInfraTestFile(t, tempDir, "values.yaml", helmValuesContent) // Should not be detected without helm context

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	helmCount := 0
	chartCount := 0
	valuesCount := 0

	for _, art := range artifacts {
		if art.Type == artifact.TypeHelmChart {
			helmCount++
			if art.Name == "Chart.yaml" {
				chartCount++
				if art.Metadata["file_type"] != "chart-definition" {
					t.Errorf("Expected file_type 'chart-definition', got '%s'", art.Metadata["file_type"])
				}
			}
			if art.Name == "values.yaml" {
				valuesCount++
				if art.Metadata["file_type"] != "values" {
					t.Errorf("Expected file_type 'values', got '%s'", art.Metadata["file_type"])
				}
			}
		}
	}

	// Should detect Chart.yaml and values.yaml in chart directory, but not standalone values.yaml
	if helmCount != 2 {
		t.Errorf("Expected 2 Helm artifacts, got %d", helmCount)
	}
	if chartCount != 1 {
		t.Errorf("Expected 1 Chart.yaml, got %d", chartCount)
	}
	if valuesCount != 1 {
		t.Errorf("Expected 1 values.yaml (in chart context), got %d", valuesCount)
	}
}

// Test Terraform files
func TestInfrastructureAnalyzerTerraform(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "main.tf", terraformContent)
	createInfraTestFile(t, tempDir, "variables.tf", terraformContent)
	createInfraTestFile(t, tempDir, "terraform.tfvars", terraformVarsContent)
	createInfraTestFile(t, tempDir, "providers.tf", terraformContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	terraformCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeTerraformConfig {
			terraformCount++

			// Check metadata
			if art.Metadata["iac_type"] != "provisioning" {
				t.Errorf("Expected iac_type 'provisioning', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "terraform" {
				t.Errorf("Expected platform 'terraform', got '%s'", art.Metadata["platform"])
			}

			// Check specific file type metadata
			if art.Name == "terraform.tfvars" && art.Metadata["file_type"] != "variables" {
				t.Errorf("Expected file_type 'variables' for tfvars, got '%s'", art.Metadata["file_type"])
			}
			// .tf files get "terraform" file_type, specific files like providers.tf
			// are handled by the general .tf case, not the specific filename case
			if strings.HasSuffix(art.Name, ".tf") && art.Metadata["file_type"] != "terraform" {
				t.Errorf("Expected file_type 'terraform' for .tf files, got '%s'", art.Metadata["file_type"])
			}
		}
	}

	if terraformCount != 4 {
		t.Errorf("Expected 4 Terraform artifacts, got %d", terraformCount)
	}
}

// Test Ansible files
func TestInfrastructureAnalyzerAnsible(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "playbook.yml", ansiblePlaybookContent)
	createInfraTestFile(t, tempDir, "site.yaml", ansiblePlaybookContent)
	createInfraTestFile(t, tempDir, "ansible.cfg", ansibleConfigContent)
	createInfraTestFile(t, tempDir, "regular.yml", regularYamlContent) // Should not be detected

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	ansibleCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeAnsiblePlaybook {
			ansibleCount++

			// Check metadata
			if art.Metadata["iac_type"] != "configuration-management" {
				t.Errorf("Expected iac_type 'configuration-management', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "ansible" {
				t.Errorf("Expected platform 'ansible', got '%s'", art.Metadata["platform"])
			}

			if art.Name == "ansible.cfg" && art.Metadata["file_type"] != "configuration" {
				t.Errorf("Expected file_type 'configuration' for ansible.cfg, got '%s'", art.Metadata["file_type"])
			}
		}
	}

	// Should detect 2 playbooks and 1 config file (3 total)
	if ansibleCount != 3 {
		t.Errorf("Expected 3 Ansible artifacts, got %d", ansibleCount)
	}
}

// Test cloud provider specific files
func TestInfrastructureAnalyzerCloudFormation(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "template.json", cloudFormationContent)
	createInfraTestFile(t, tempDir, "stack.yaml", cloudFormationContent)
	createInfraTestFile(t, tempDir, "regular.json", regularJsonContent) // Should not be detected

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	cfCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeCloudFormation {
			cfCount++

			// Check metadata
			if art.Metadata["iac_type"] != "cloud-provisioning" {
				t.Errorf("Expected iac_type 'cloud-provisioning', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "aws-cloudformation" {
				t.Errorf("Expected platform 'aws-cloudformation', got '%s'", art.Metadata["platform"])
			}
		}
	}

	// Should only detect CloudFormation templates, not regular JSON
	if cfCount != 2 {
		t.Errorf("Expected 2 CloudFormation artifacts, got %d", cfCount)
	}
}

func TestInfrastructureAnalyzerAWSCDK(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "app.ts", awsCdkContent)
	createInfraTestFile(t, tempDir, "stack.js", awsCdkContent)
	createInfraTestFile(t, tempDir, "regular.ts", "console.log('Hello World');") // Should not be detected

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	cdkCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeAWSCDK {
			cdkCount++

			// Check metadata
			if art.Metadata["iac_type"] != "cloud-provisioning" {
				t.Errorf("Expected iac_type 'cloud-provisioning', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "aws-cdk" {
				t.Errorf("Expected platform 'aws-cdk', got '%s'", art.Metadata["platform"])
			}
		}
	}

	// Should only detect CDK files, not regular TypeScript
	if cdkCount != 2 {
		t.Errorf("Expected 2 AWS CDK artifacts, got %d", cdkCount)
	}
}

func TestInfrastructureAnalyzerPulumi(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, "index.ts", pulumiContent)
	createInfraTestFile(t, tempDir, "Pulumi.yaml", pulumiConfigContent)
	createInfraTestFile(t, tempDir, "regular.ts", "console.log('Hello');") // Should not be detected

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	pulumiCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypePulumi {
			pulumiCount++

			// Check metadata
			if art.Metadata["iac_type"] != "cloud-provisioning" {
				t.Errorf("Expected iac_type 'cloud-provisioning', got '%s'", art.Metadata["iac_type"])
			}
			if art.Metadata["platform"] != "pulumi" {
				t.Errorf("Expected platform 'pulumi', got '%s'", art.Metadata["platform"])
			}

			if art.Name == "Pulumi.yaml" && art.Metadata["file_type"] != "project-config" {
				t.Errorf("Expected file_type 'project-config' for Pulumi.yaml, got '%s'", art.Metadata["file_type"])
			}
		}
	}

	// Should detect Pulumi files but not regular TypeScript
	if pulumiCount != 2 {
		t.Errorf("Expected 2 Pulumi artifacts, got %d", pulumiCount)
	}
}

// Test edge cases and error handling
func TestInfrastructureAnalyzerEmptyDirectory(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, expected nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Expected 0 artifacts in empty directory, got %d", len(artifacts))
	}
}

func TestInfrastructureAnalyzerNonexistentDirectory(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: "/nonexistent/path",
	}

	ctx := context.Background()
	artifacts, _ := analyzer.Scan(ctx, source)

	// filepath.Walk might not return an error for non-existent paths on all systems
	// so we just check that no artifacts were found
	if len(artifacts) != 0 {
		t.Errorf("Expected 0 artifacts for nonexistent directory, got %d", len(artifacts))
	}
}

func TestInfrastructureAnalyzerIgnoreNonInfrastructureFiles(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Create non-infrastructure files
	createInfraTestFile(t, tempDir, "README.md", "# Test Project")
	createInfraTestFile(t, tempDir, "main.go", "package main")
	createInfraTestFile(t, tempDir, "config.json", regularJsonContent)
	createInfraTestFile(t, tempDir, "data.yaml", regularYamlContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, expected nil", err)
	}

	if len(artifacts) != 0 {
		t.Errorf("Expected 0 artifacts from non-infrastructure files, got %d", len(artifacts))
	}
}

func TestInfrastructureAnalyzerCaseInsensitive(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Create files with different cases
	createInfraTestFile(t, tempDir, "DOCKERFILE", dockerfileContent)
	createInfraTestFile(t, tempDir, "VAGRANTFILE", vagrantFileContent)
	createInfraTestFile(t, tempDir, "Docker-Compose.YML", dockerComposeContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v, expected nil", err)
	}

	if len(artifacts) == 0 {
		t.Error("Expected artifacts from case-insensitive file matching, got none")
	}

	// Check that we found different infrastructure types
	foundTypes := make(map[artifact.Type]bool)
	for _, art := range artifacts {
		foundTypes[art.Type] = true
	}

	expectedTypes := []artifact.Type{
		artifact.TypeDockerfile,
		artifact.TypeVagrantfile,
		artifact.TypeDockerCompose,
	}

	for _, expectedType := range expectedTypes {
		if !foundTypes[expectedType] {
			t.Errorf("Expected to find artifacts of type %v", expectedType)
		}
	}
}

func TestInfrastructureAnalyzerNestedDirectories(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Create nested structure with different infrastructure files
	createInfraTestFile(t, tempDir, "frontend/Dockerfile", dockerfileContent)
	createInfraTestFile(t, tempDir, "backend/Dockerfile", dockerfileContent)
	createInfraTestFile(t, tempDir, "k8s/manifests/deployment.yaml", kubernetesManifestContent)
	createInfraTestFile(t, tempDir, "infrastructure/terraform/main.tf", terraformContent)
	createInfraTestFile(t, tempDir, "ansible/playbooks/setup.yml", ansiblePlaybookContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	if len(artifacts) == 0 {
		t.Error("Expected artifacts to be found in nested directories, got none")
		return
	}

	// Check that we found different infrastructure types in nested dirs
	foundTypes := make(map[artifact.Type]bool)
	for _, art := range artifacts {
		foundTypes[art.Type] = true
	}

	expectedTypes := []artifact.Type{
		artifact.TypeDockerfile,
		artifact.TypeKubernetesManifest,
		artifact.TypeTerraformConfig,
		artifact.TypeAnsiblePlaybook,
	}

	for _, expectedType := range expectedTypes {
		if !foundTypes[expectedType] {
			t.Errorf("Expected to find artifacts of type %v in nested directories", expectedType)
		}
	}

	// Check that Dockerfile count is 2 (frontend and backend)
	dockerfileCount := 0
	for _, art := range artifacts {
		if art.Type == artifact.TypeDockerfile {
			dockerfileCount++
		}
	}
	if dockerfileCount != 2 {
		t.Errorf("Expected 2 Dockerfiles in nested directories, got %d", dockerfileCount)
	}
}

func TestInfrastructureAnalyzerArtifactMetadata(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	createInfraTestFile(t, tempDir, infraDockerfileFile, dockerfileContent)

	source := artifact.Source{
		Type:     artifact.SourceTypeFilesystem,
		Location: tempDir,
	}

	ctx := context.Background()
	artifacts, err := analyzer.Scan(ctx, source)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
		return
	}

	if len(artifacts) != 1 {
		t.Errorf("Expected 1 artifact, got %d", len(artifacts))
		return
	}

	art := artifacts[0]

	// Check basic artifact properties
	if art.Name != infraDockerfileFile {
		t.Errorf("Expected name '%s', got '%s'", infraDockerfileFile, art.Name)
	}
	if art.Type != artifact.TypeDockerfile {
		t.Errorf("Expected type %v, got %v", artifact.TypeDockerfile, art.Type)
	}
	if art.Size == 0 {
		t.Error("Expected non-zero size")
	}
	if art.ModTime == nil {
		t.Error("Expected non-nil ModTime")
	}
	if art.Permissions == "" {
		t.Error("Expected non-empty permissions")
	}

	// Check metadata
	expectedMetadata := map[string]string{
		"iac_type":  "container",
		"platform":  "docker",
		"file_type": "dockerfile",
	}

	for key, expectedValue := range expectedMetadata {
		if actualValue, ok := art.Metadata[key]; !ok {
			t.Errorf("Expected metadata key '%s' not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected metadata '%s' to be '%s', got '%s'", key, expectedValue, actualValue)
		}
	}
}

// Test specific detection methods
func TestInfrastructureAnalyzerIsKubernetesManifest(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid Kubernetes manifest
	k8sFile := createInfraTestFile(t, tempDir, "valid-k8s.yaml", kubernetesManifestContent)
	if !analyzer.isKubernetesManifest(k8sFile) {
		t.Error("Expected valid Kubernetes manifest to be detected")
	}

	// Test regular YAML file
	regularFile := createInfraTestFile(t, tempDir, "regular.yaml", regularYamlContent)
	if analyzer.isKubernetesManifest(regularFile) {
		t.Error("Expected regular YAML to not be detected as Kubernetes manifest")
	}

	// Test nonexistent file
	if analyzer.isKubernetesManifest("/nonexistent/file.yaml") {
		t.Error("Expected nonexistent file to not be detected as Kubernetes manifest")
	}
}

func TestInfrastructureAnalyzerIsAnsiblePlaybook(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid Ansible playbook
	ansibleFile := createInfraTestFile(t, tempDir, "valid-ansible.yml", ansiblePlaybookContent)
	if !analyzer.isAnsiblePlaybook(ansibleFile) {
		t.Error("Expected valid Ansible playbook to be detected")
	}

	// Test regular YAML file
	regularFile := createInfraTestFile(t, tempDir, "regular.yml", regularYamlContent)
	if analyzer.isAnsiblePlaybook(regularFile) {
		t.Error("Expected regular YAML to not be detected as Ansible playbook")
	}
}

func TestInfrastructureAnalyzerIsCloudFormationTemplate(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid CloudFormation template
	cfFile := createInfraTestFile(t, tempDir, "valid-cf.json", cloudFormationContent)
	if !analyzer.isCloudFormationTemplate(cfFile) {
		t.Error("Expected valid CloudFormation template to be detected")
	}

	// Test regular JSON file
	regularFile := createInfraTestFile(t, tempDir, "regular.json", regularJsonContent)
	if analyzer.isCloudFormationTemplate(regularFile) {
		t.Error("Expected regular JSON to not be detected as CloudFormation template")
	}
}

func TestInfrastructureAnalyzerIsAWSCDKFile(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid AWS CDK file
	cdkFile := createInfraTestFile(t, tempDir, "valid-cdk.ts", awsCdkContent)
	if !analyzer.isAWSCDKFile(cdkFile) {
		t.Error("Expected valid AWS CDK file to be detected")
	}

	// Test regular TypeScript file
	regularFile := createInfraTestFile(t, tempDir, "regular.ts", "console.log('Hello World');")
	if analyzer.isAWSCDKFile(regularFile) {
		t.Error("Expected regular TypeScript to not be detected as AWS CDK")
	}
}

func TestInfrastructureAnalyzerIsPulumiProject(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid Pulumi file
	pulumiFile := createInfraTestFile(t, tempDir, "valid-pulumi.ts", pulumiContent)
	if !analyzer.isPulumiProject(pulumiFile) {
		t.Error("Expected valid Pulumi file to be detected")
	}

	// Test regular TypeScript file
	regularFile := createInfraTestFile(t, tempDir, "regular.ts", "console.log('Hello');")
	if analyzer.isPulumiProject(regularFile) {
		t.Error("Expected regular TypeScript to not be detected as Pulumi")
	}
}

func TestInfrastructureAnalyzerIsAzureARMTemplate(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid Azure ARM template
	armFile := createInfraTestFile(t, tempDir, "valid-arm.json", azureArmContent)
	if !analyzer.isAzureARMTemplate(armFile) {
		t.Error("Expected valid Azure ARM template to be detected")
	}

	// Test regular JSON file
	regularFile := createInfraTestFile(t, tempDir, "regular.json", regularJsonContent)
	if analyzer.isAzureARMTemplate(regularFile) {
		t.Error("Expected regular JSON to not be detected as Azure ARM template")
	}
}

func TestInfrastructureAnalyzerIsGoogleCloudDeployment(t *testing.T) {
	analyzer := NewInfrastructureAnalyzer()
	tempDir := t.TempDir()

	// Test valid Google Cloud Deployment file
	gcdFile := createInfraTestFile(t, tempDir, "valid-gcd.yaml", googleCloudDeployContent)
	if !analyzer.isGoogleCloudDeployment(gcdFile) {
		t.Error("Expected valid Google Cloud Deployment file to be detected")
	}

	// Test regular YAML file
	regularFile := createInfraTestFile(t, tempDir, "regular.yaml", regularYamlContent)
	if analyzer.isGoogleCloudDeployment(regularFile) {
		t.Error("Expected regular YAML to not be detected as Google Cloud Deployment")
	}
}
