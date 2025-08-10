# Complete DevOps & Cloud Security Scenarios with Solutions

## Terraform Scenarios & Solutions

### 1. Multi-Environment Deployment

**Scenario**: You need to deploy identical infrastructure across dev, staging, and production environments with different configurations. How would you structure your Terraform code to avoid duplication while maintaining environment-specific customizations?

**Solution**:
```hcl
# Directory structure:
# ├── modules/
# │   └── app-infrastructure/
# │       ├── main.tf
# │       ├── variables.tf
# │       └── outputs.tf
# ├── environments/
# │   ├── dev/
# │   ├── staging/
# │   └── prod/
# └── terraform.tfvars.example

# modules/app-infrastructure/main.tf
resource "aws_instance" "app" {
  count           = var.instance_count
  ami             = var.ami_id
  instance_type   = var.instance_type
  subnet_id       = var.subnet_ids[count.index % length(var.subnet_ids)]
  security_groups = [aws_security_group.app.id]
  
  tags = merge(var.common_tags, {
    Name = "${var.environment}-app-${count.index + 1}"
  })
}

# environments/prod/main.tf
module "app_infrastructure" {
  source = "../../modules/app-infrastructure"
  
  environment     = "prod"
  instance_count  = 3
  instance_type   = "t3.large"
  ami_id          = var.prod_ami_id
  
  common_tags = {
    Environment = "prod"
    Project     = var.project_name
    Owner       = var.team_name
  }
}

# Use terraform workspaces or separate state files
terraform workspace new prod
terraform workspace select prod
```

### 2. State File Recovery

**Scenario**: Your team accidentally corrupted the Terraform state file for a critical production environment. The infrastructure is still running, but Terraform can't manage it.

**Solution**:
```bash
# Step 1: Backup the corrupted state
cp terraform.tfstate terraform.tfstate.corrupted.bak

# Step 2: Create a new empty state
terraform init -reconfigure

# Step 3: Import existing resources
# First, identify all resources that need to be imported
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0]]' --output table

# Import each resource individually
terraform import aws_instance.web i-1234567890abcdef0
terraform import aws_security_group.web_sg sg-0123456789abcdef0

# Step 4: Verify the state
terraform plan
# Should show "No changes" if import was successful

# Step 5: Use terraform import with for_each for multiple resources
# Create a script to automate imports
cat > import.sh << 'EOF'
#!/bin/bash
for instance_id in $(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --output text); do
  terraform import "aws_instance.web[\"$instance_id\"]" $instance_id
done
EOF
```

### 3. Terraform Security - Secrets Management

**Scenario**: Your Terraform configuration needs to create resources that require sensitive data without exposing them in state files or version control.

**Solution**:
```hcl
# Use AWS Systems Manager Parameter Store
data "aws_ssm_parameter" "db_password" {
  name            = "/myapp/prod/db_password"
  with_decryption = true
}

resource "aws_db_instance" "main" {
  identifier     = "myapp-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  # Use the retrieved password
  password = data.aws_ssm_parameter.db_password.value
  
  # Other configurations...
  skip_final_snapshot = true
}

# Alternative: Use random password generation
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "aws_ssm_parameter" "db_password" {
  name  = "/myapp/${var.environment}/db_password"
  type  = "SecureString"
  value = random_password.db_password.result
}

# For Terraform Cloud/Enterprise
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

# Mark outputs as sensitive
output "db_endpoint" {
  value     = aws_db_instance.main.endpoint
  sensitive = false
}

output "db_password" {
  value     = random_password.db_password.result
  sensitive = true
}
```

## Kubernetes Scenarios & Solutions

### 4. Pod Scheduling Troubleshooting

**Scenario**: Your application pods are not being scheduled on certain nodes despite having available resources. The nodes show as "Ready" but pods remain in "Pending" state.

**Solution**:
```bash
# Step 1: Check pod status and events
kubectl describe pod <pod-name>
kubectl get events --sort-by=.metadata.creationTimestamp

# Step 2: Check node conditions and capacity
kubectl describe nodes
kubectl top nodes

# Step 3: Common issues and solutions

# Issue: Node taints
kubectl describe node <node-name> | grep -A5 Taints
# Solution: Add tolerations to pod spec
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  tolerations:
  - key: "dedicated"
    operator: "Equal"
    value: "app"
    effect: "NoSchedule"
  containers:
  - name: app
    image: nginx

# Issue: Resource requests exceeding available capacity
# Check actual resource usage vs requests
kubectl describe node <node-name> | grep -A10 "Allocated resources"

# Solution: Adjust resource requests or add more nodes
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"

# Issue: Node selectors or affinity rules
# Check for nodeSelector or affinity constraints
kubectl get pod <pod-name> -o yaml | grep -A10 nodeSelector

# Issue: PodDisruptionBudget preventing scheduling
kubectl get pdb --all-namespaces
```

### 5. Kubernetes Security - RBAC Implementation

**Scenario**: A developer accidentally deleted critical resources because they had cluster-admin privileges. Implement proper RBAC to prevent this while ensuring developers can still work effectively.

**Solution**:
```yaml
# Create namespace-specific roles
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: developer-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods/log", "pods/exec"]
  verbs: ["get", "list"]

---
# Bind role to users/groups
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: development
subjects:
- kind: User
  name: developer@company.com
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io

---
# Read-only cluster role for monitoring
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "namespaces"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["nodes", "pods"]
  verbs: ["get", "list"]

---
# Service account for applications
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

---
# Implement admission controllers for additional security
apiVersion: v1
kind: ConfigMap
metadata:
  name: admission-config
data:
  config.yaml: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AdmissionConfiguration
    plugins:
    - name: ValidatingAdmissionWebhook
      configuration:
        apiVersion: apiserver.config.k8s.io/v1
        kind: WebhookAdmissionConfiguration
        webhooks:
        - name: security-policy.company.com
          clientConfig:
            service:
              name: security-webhook
              namespace: kube-system
              path: "/validate"
          rules:
          - operations: ["CREATE", "UPDATE"]
            apiGroups: [""]
            apiVersions: ["v1"]
            resources: ["pods"]
```

## Docker Scenarios & Solutions

### 6. Multi-Stage Build Optimization

**Scenario**: Your Docker image is 2GB in size and takes too long to build and deploy. Optimize it using multi-stage builds and other techniques.

**Solution**:
```dockerfile
# Before: Single stage build (2GB)
# FROM node:16
# WORKDIR /app
# COPY . .
# RUN npm install
# RUN npm run build
# EXPOSE 3000
# CMD ["npm", "start"]

# After: Optimized multi-stage build
# Stage 1: Build stage
FROM node:16-alpine AS builder
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
RUN npm ci --only=production

# Copy source and build
COPY . .
RUN npm run build

# Stage 2: Production stage
FROM node:16-alpine AS production
WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package*.json ./

USER nextjs

EXPOSE 3000

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]

# Additional optimizations
# .dockerignore file
node_modules
npm-debug.log
Dockerfile
.dockerignore
.git
.gitignore
README.md
.env
.nyc_output
coverage
.nyc_output

# Build optimization script
build-optimized.sh:
#!/bin/bash
# Enable BuildKit for better caching
export DOCKER_BUILDKIT=1

# Build with cache mounts
docker build \
  --cache-from myapp:cache \
  --tag myapp:latest \
  --tag myapp:cache \
  --target production \
  .

# Multi-architecture build
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag myapp:latest \
  --push .
```

### 7. Docker Security - Container Runtime Security

**Scenario**: You suspect a container might be compromised and running unauthorized processes. How would you monitor and detect such activities?

**Solution**:
```bash
# Real-time monitoring setup
# 1. Install Falco for runtime security monitoring
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set-file rules.rules=/path/to/custom-rules.yaml

# Custom Falco rules for container monitoring
# /path/to/custom-rules.yaml
- rule: Unexpected process in container
  desc: Detect unexpected processes in containers
  condition: >
    spawned_process and container and
    not proc.name in (node, npm, nginx, apache2, mysqld)
  output: >
    Unexpected process spawned in container 
    (user=%user.name command=%proc.cmdline container=%container.name image=%container.image)
  priority: WARNING

- rule: Container privilege escalation
  desc: Detect privilege escalation attempts
  condition: >
    spawned_process and container and
    proc.name in (sudo, su, setuid, setgid)
  output: >
    Privilege escalation attempt in container
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: HIGH

# 2. Runtime security with AppArmor/SELinux
# AppArmor profile for containers
cat > /etc/apparmor.d/docker-nginx << 'EOF'
#include <tunables/global>

profile docker-nginx flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Deny network admin capabilities
  deny capability net_admin,
  deny capability sys_admin,
  
  # Allow only necessary file access
  /usr/sbin/nginx r,
  /var/log/nginx/ rw,
  /etc/nginx/ r,
  
  # Deny access to host system
  deny /proc/sys/** wklx,
  deny /sys/** wklx,
}
EOF

# 3. Container monitoring script
cat > monitor-containers.sh << 'EOF'
#!/bin/bash

# Monitor running processes in containers
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | while IFS=$'\t' read name image status; do
  if [[ "$name" != "NAMES" ]]; then
    echo "=== Monitoring container: $name ==="
    
    # Check running processes
    echo "Processes:"
    docker exec $name ps aux
    
    # Check network connections
    echo "Network connections:"
    docker exec $name netstat -tulpn 2>/dev/null || echo "netstat not available"
    
    # Check file system changes
    echo "File system changes:"
    docker diff $name
    
    echo "=========================="
  fi
done
EOF

# 4. Security scanning with Trivy
# Scan running containers
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL nginx:latest

# 5. Implement container security policies
# Docker Compose with security constraints
version: '3.8'
services:
  app:
    image: myapp:latest
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-nginx
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
    read_only: true
    tmpfs:
      - /tmp:size=100M,noexec,nosuid,nodev
    user: "1000:1000"
    volumes:
      - ./app-data:/app/data:ro
```

## AWS Scenarios & Solutions

### 8. VPC Design for Multi-Tier Application

**Scenario**: Design a VPC architecture for a multi-tier application across 3 availability zones with public and private subnets, NAT gateways, and proper routing for high availability and security.

**Solution**:
```hcl
# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.environment}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "${var.environment}-igw"
  }
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Public subnets (one per AZ)
resource "aws_subnet" "public" {
  count = 3
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.environment}-public-${count.index + 1}"
    Type = "Public"
  }
}

# Private subnets for application tier
resource "aws_subnet" "private_app" {
  count = 3
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name = "${var.environment}-private-app-${count.index + 1}"
    Type = "Private"
    Tier = "Application"
  }
}

# Private subnets for database tier
resource "aws_subnet" "private_db" {
  count = 3
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 20}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name = "${var.environment}-private-db-${count.index + 1}"
    Type = "Private"
    Tier = "Database"
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count = 3
  
  domain = "vpc"
  
  tags = {
    Name = "${var.environment}-eip-nat-${count.index + 1}"
  }
  
  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways
resource "aws_nat_gateway" "main" {
  count = 3
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = {
    Name = "${var.environment}-nat-${count.index + 1}"
  }
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name = "${var.environment}-rt-public"
  }
}

# Route tables for private subnets (one per AZ for HA)
resource "aws_route_table" "private" {
  count = 3
  
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  
  tags = {
    Name = "${var.environment}-rt-private-${count.index + 1}"
  }
}

# Route table associations
resource "aws_route_table_association" "public" {
  count = 3
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_app" {
  count = 3
  
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "private_db" {
  count = 3
  
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security Groups
resource "aws_security_group" "alb" {
  name_prefix = "${var.environment}-alb-"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name_prefix = "${var.environment}-app-"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name_prefix = "${var.environment}-db-"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}
```

### 9. AWS Security - IAM Policy Audit

**Scenario**: You suspect some IAM policies in your AWS account are overly permissive. How would you audit and remediate IAM permissions across your organization?

**Solution**:
```bash
# 1. AWS CLI scripts for IAM audit
#!/bin/bash
# iam-audit.sh

echo "=== IAM Security Audit Report ==="
echo "Generated on: $(date)"
echo ""

# Find users with admin access
echo "1. Users with Administrative Access:"
aws iam get-account-authorization-details --filter User | \
jq -r '.UserDetailList[] | select(.UserPolicyList[].PolicyDocument.Statement[]?.Effect == "Allow" and .UserPolicyList[].PolicyDocument.Statement[]?.Action == "*") | .UserName'

# Find roles with admin access
echo ""
echo "2. Roles with Administrative Access:"
aws iam list-roles | jq -r '.Roles[].RoleName' | while read role; do
  aws iam list-attached-role-policies --role-name "$role" | \
  jq -r '.AttachedPolicies[] | select(.PolicyArn | contains("AdministratorAccess")) | "Role: '$role' has AdministratorAccess"'
done

# Check for unused access keys
echo ""
echo "3. Unused Access Keys (older than 90 days):"
aws iam list-users | jq -r '.Users[].UserName' | while read user; do
  aws iam list-access-keys --user-name "$user" | \
  jq -r --arg user "$user" '.AccessKeyMetadata[] | select(.Status == "Active") | "User: \($user), Key: \(.AccessKeyId), Created: \(.CreateDate)"'
done

# 2. Implement least privilege policies
# Example: S3 access policy with conditions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::myapp-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2024-01-01T00:00:00Z"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}

# 3. Terraform for IAM remediation
resource "aws_iam_policy" "developer_policy" {
  name        = "DeveloperPolicy"
  description = "Least privilege policy for developers"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:GetObject",
          "s3:ListBucket",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::dev-bucket/*",
          "arn:aws:s3:::staging-bucket/*"
        ]
      }
    ]
  })
}

# 4. Automated compliance checking
resource "aws_config_configuration_recorder" "main" {
  name     = "security-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_config_rule" "iam_policy_check" {
  name = "iam-policy-no-statements-with-admin-access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# 5. Access Analyzer for unused access
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "security-analyzer"
  type          = "ACCOUNT"

  tags = {
    Name = "SecurityAnalyzer"
  }
}
```

## Azure Scenarios & Solutions

### 10. Azure Security - Conditional Access Implementation

**Scenario**: You need to implement conditional access policies that balance security with user experience for a global organization.

**Solution**:
```powershell
# PowerShell script for Azure AD Conditional Access
Connect-AzureAD

# 1. Risk-based conditional access policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = @("break-glass-account-id")

# Location-based conditions
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = @("AllTrusted")
$conditions.Locations.ExcludeLocations = @("MfaCompliantLocation")

# Grant controls with MFA requirement
$grantControls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$grantControls.BuiltInControls = @("mfa", "compliantDevice")
$grantControls.Operator = "OR"

# Create the policy
New-AzureADMSConditionalAccessPolicy -DisplayName "Global MFA Policy" `
  -State "Enabled" `
  -Conditions $conditions `
  -GrantControls $grantControls

# 2. Application-specific policies using Azure CLI
# High-risk applications require stronger authentication
az ad signed-in-user show --query userPrincipalName -o tsv

cat > conditional-access-policies.json << 'EOF'
{
  "displayName": "High Risk Apps - Require MFA and Compliant Device",
  "state": "enabled",
  "conditions": {
    "applications": {
      "includeApplications": ["finance-app-id", "hr-app-id"]
    },
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": ["emergency-access-account"]
    },
    "locations": {
      "includeLocations": ["All"]
    },
    "signInRiskLevels": ["high", "medium"],
    "userRiskLevels": ["high"]
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice"]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": 4,
      "type": "hours"
    }
  }
}
EOF

# 3. Terraform implementation for Azure Conditional Access
terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

# Named locations for trusted IPs
resource "azuread_named_location" "trusted_ips" {
  display_name = "TrustedCorpNetwork"
  
  ip {
    ip_ranges_or_fqdns = [
      "203.0.113.0/24",  # Corporate office
      "198.51.100.0/24"  # Branch office
    ]
    trusted = true
  }
}

# Conditional access policy for external access
resource "azuread_conditional_access_policy" "external_access" {
  display_name = "External Access Requires MFA"
  state        = "enabled"
  
  conditions {
    applications {
      included_applications = ["All"]
      excluded_applications = ["Office365"]
    }
    
    users {
      included_users = ["All"]
      excluded_users = [azuread_user.break_glass.object_id]
    }
    
    locations {
      included_locations = ["All"]
      excluded_locations = [azuread_named_location.trusted_ips.id]
    }
  }
  
  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
  
  session_controls {
    sign_in_frequency         = 8
    sign_in_frequency_period  = "hours"
    cloud_app_security_policy = "monitorOnly"
  }
}

# 4. PowerShell script for policy validation
# Test-ConditionalAccessPolicies.ps1
function Test-ConditionalAccessPolicies {
    $policies = Get-AzureADMSConditionalAccessPolicy
    
    foreach ($policy in $policies) {
        Write-Host "Testing Policy: $($policy.DisplayName)"
        
        # Check for overly broad policies
        if ($policy.Conditions.Applications.IncludeApplications -contains "All" -and 
            $policy.Conditions.Users.IncludeUsers -contains "All" -and
            $policy.Conditions.Locations.IncludeLocations -contains "All") {
            Write-Warning "Policy '$($policy.DisplayName)' may be too broad"
        }
        
        # Check for emergency access exclusions
        if (-not $policy.Conditions.Users.ExcludeUsers) {
            Write-Warning "Policy '$($policy.DisplayName)' has no emergency access exclusions"
        }
    }
}
```

## Cloud Security Scenarios & Solutions

### 11. Zero Trust Architecture Implementation

**Scenario**: You need to implement a zero-trust security model for your cloud infrastructure across all layers.

**Solution**:
```yaml
# 1. Identity and Access Management Layer
# Azure AD/AWS SSO Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: zero-trust-config
data:
  identity-policy.yaml: |
    principles:
      - verify_explicitly
      - least_privilege_access
      - assume_breach
    
    policies:
      authentication:
        - multi_factor_required: true
        - passwordless_preferred: true
        - risk_based_access: true
      
      authorization:
        - just_in_time_access: true
        - privileged_access_workstations: true
        - continuous_verification: true

# 2. Network Security - Micro-segmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: zero-trust-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS only

# 3. Application Layer Security
# Implement mutual TLS with Istio
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT

---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: web-app-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: web-app
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*"]
  - when:
    - key: source.ip
      values: ["10.0.0.0/16"]

# 4. Data Protection Layer
apiVersion: v1
kind: Secret
metadata:
  name: database-encryption-key
  namespace: production
  annotations:
    kubernetes.io/encryption: "required"
type: Opaque
data:
  key: <base64-encoded-encryption-key>

---
# Terraform for AWS KMS encryption
resource "aws_kms_key" "zero_trust" {
  description             = "Zero Trust Data Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key for encryption/decryption"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.app_role.arn,
            aws_iam_role.database_role.arn
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.us-east-1.amazonaws.com",
              "rds.us-east-1.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

# 5. Monitoring and Analytics
# CloudWatch/Azure Monitor configuration
resource "aws_cloudwatch_log_group" "zero_trust_logs" {
  name              = "/zero-trust/security-events"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.zero_trust.arn
}

resource "aws_cloudwatch_metric_filter" "failed_authentication" {
  name           = "FailedAuthentication"
  log_group_name = aws_cloudwatch_log_group.zero_trust_logs.name
  pattern        = "[timestamp, request_id, ERROR, \"Authentication failed\"]"
  
  metric_transformation {
    name      = "FailedAuthenticationAttempts"
    namespace = "ZeroTrust/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "suspicious_activity" {
  alarm_name          = "SuspiciousAuthenticationActivity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FailedAuthenticationAttempts"
  namespace           = "ZeroTrust/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors failed authentication attempts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

### 12. Data Breach Response

**Scenario**: You've detected unauthorized access to your cloud storage containing customer data. What immediate and long-term actions would you take?

**Solution**:
```bash
# Immediate Response Plan (First 30 minutes)

# 1. Incident Response Script
#!/bin/bash
# incident-response.sh

INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/incident-${INCIDENT_ID}.log"

echo "=== INCIDENT RESPONSE INITIATED ===" | tee -a $LOG_FILE
echo "Incident ID: $INCIDENT_ID" | tee -a $LOG_FILE
echo "Start Time: $(date)" | tee -a $LOG_FILE

# Step 1: Immediate containment
echo "STEP 1: CONTAINMENT" | tee -a $LOG_FILE

# Disable compromised access keys (AWS)
COMPROMISED_ACCESS_KEY="AKIA..."
aws iam delete-access-key --access-key-id $COMPROMISED_ACCESS_KEY --user-name compromised-user | tee -a $LOG_FILE

# Block suspicious IP addresses
SUSPICIOUS_IPS=("192.0.2.1" "203.0.113.5")
for ip in "${SUSPICIOUS_IPS[@]}"; do
  # AWS WAF
  aws wafv2 update-ip-set \
    --scope CLOUDFRONT \
    --id suspicious-ips-set \
    --addresses $ip/32 | tee -a $LOG_FILE
  
  # Azure NSG
  az network nsg rule create \
    --resource-group security-rg \
    --nsg-name production-nsg \
    --name "Block-$ip" \
    --priority 100 \
    --source-address-prefixes $ip \
    --access Deny | tee -a $LOG_FILE
done

# Step 2: Evidence preservation
echo "STEP 2: EVIDENCE PRESERVATION" | tee -a $LOG_FILE

# AWS CloudTrail analysis
aws logs start-query \
  --log-group-name CloudTrail/SecurityEvents \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, sourceIPAddress, userIdentity.userName, eventName | filter sourceIPAddress like /192.0.2/' | tee -a $LOG_FILE

# Export security logs
aws s3 sync s3://security-logs-bucket/$(date +%Y/%m/%d) ./evidence/aws-logs/ | tee -a $LOG_FILE

# Step 3: Impact assessment
echo "STEP 3: IMPACT ASSESSMENT" | tee -a $LOG_FILE

# Check accessed resources
aws s3api list-objects-v2 \
  --bucket customer-data-bucket \
  --query 'Contents[?LastModified>=`2024-01-01T00:00:00.000Z`].[Key,LastModified,Size]' \
  --output table | tee -a $LOG_FILE

# 2. Forensic Analysis Terraform Configuration
resource "aws_s3_bucket" "forensic_data" {
  bucket = "forensic-evidence-${random_id.bucket_suffix.hex}"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  lifecycle_rule {
    enabled = true
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

# CloudTrail for forensics
resource "aws_cloudtrail" "forensic_trail" {
  name           = "forensic-investigation-trail"
  s3_bucket_name = aws_s3_bucket.forensic_data.bucket
  
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::customer-data-bucket/*"]
    }
  }
  
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
}

# 3. Long-term remediation
# Enhanced monitoring with AWS Config
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  
  depends_on = [aws_config_configuration_recorder.recorder]
}

# 4. Customer notification template
cat > customer-notification.md << 'EOF'
# Security Incident Notification

**Date**: $(date)
**Incident ID**: $INCIDENT_ID

## What Happened
We detected unauthorized access to our cloud storage systems on [DATE]. Our security team immediately contained the incident and began investigation.

## What Information Was Involved
- Customer names and email addresses
- Account creation dates
- No payment information or passwords were accessed

## What We're Doing
1. Immediately secured the affected systems
2. Implemented additional security measures
3. Working with law enforcement and security experts
4. Notifying affected customers within 72 hours

## What You Can Do
- Monitor your accounts for suspicious activity
- Consider changing passwords as a precaution
- We will provide free credit monitoring services

## Contact Information
Security Hotline: 1-800-SECURITY
Email: security@company.com
EOF

# 5. Recovery and hardening script
cat > post-incident-hardening.sh << 'EOF'
#!/bin/bash

# Rotate all API keys and secrets
echo "Rotating API keys..."
aws iam list-access-keys --user-name production-service | \
jq -r '.AccessKeyMetadata[].AccessKeyId' | while read key; do
  aws iam create-access-key --user-name production-service
  # Update application with new key, then delete old one
  aws iam delete-access-key --access-key-id $key --user-name production-service
done

# Update all security groups to be more restrictive
echo "Hardening security groups..."
aws ec2 describe-security-groups --query 'SecurityGroups[?GroupName!=`default`]' | \
jq -r '.[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0") | .GroupId' | \
while read sg; do
  echo "Found overly permissive security group: $sg"
  # Implement specific remediation based on your requirements
done

# Enable additional monitoring
echo "Enabling enhanced monitoring..."
aws s3api put-bucket-notification-configuration \
  --bucket customer-data-bucket \
  --notification-configuration file://bucket-notification.json

# bucket-notification.json content for real-time monitoring
{
  "CloudWatchConfigurations": [
    {
      "Id": "ObjectCreatedEvents",
      "CloudWatchConfiguration": {
        "LogGroupName": "/aws/s3/access-logs"
      },
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [
            {
              "Name": "prefix",
              "Value": "sensitive/"
            }
          ]
        }
      }
    }
  ]
}
EOF
```

## CI/CD Scenarios & Solutions

### 13. Secure Pipeline Implementation

**Scenario**: Your CI/CD pipeline has access to production systems and credentials. How would you secure the pipeline against attacks and credential theft?

**Solution**:
```yaml
# 1. GitLab CI/CD with security controls
# .gitlab-ci.yml
stages:
  - security-scan
  - build
  - test
  - security-test
  - deploy

variables:
  DOCKER_TLS_CERTDIR: "/certs"
  SECURE_FILES_DOWNLOAD_PATH: '/tmp'

# Security scanning stage
sast:
  stage: security-scan
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/semgrep:latest
  script:
    - semgrep --config=auto --json --output=sast-report.json .
  artifacts:
    reports:
      sast: sast-report.json
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

dependency_scanning:
  stage: security-scan
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium:latest
  script:
    - /analyzer run
  artifacts:
    reports:
      dependency_scanning: dependency-scanning-report.json

# Secure build stage
build:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  before_script:
    # Verify base image integrity
    - docker trust inspect --pretty $BASE_IMAGE
    - cosign verify $BASE_IMAGE
  script:
    # Build with security scanning
    - docker build --target production -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock 
        aquasec/trivy image --exit-code 1 --severity HIGH,CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Secure deployment with approval
deploy_production:
  stage: deploy
  image: kubectl:latest
  script:
    # Verify deployment artifacts
    - cosign verify $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - kubectl apply -f k8s/production/ --dry-run=client
    - kubectl apply -f k8s/production/
    - kubectl rollout status deployment/myapp
  environment:
    name: production
    url: https://prod.example.com
  when: manual
  only:
    - main
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: manual

# 2. GitHub Actions with security
# .github/workflows/secure-deploy.yml
name: Secure CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
    - uses: actions/checkout@v4
    
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: javascript, python
    
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
    
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/owasp-top-ten

  build-and-scan:
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  deploy:
    needs: build-and-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: ${{ secrets.AWS_DEPLOYMENT_ROLE }}
        aws-region: us-east-1
        role-session-name: GitHubActions
    
    - name: Verify image signature
      run: |
        cosign verify ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
          --certificate-identity https://token.actions.githubusercontent.com \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com
    
    - name: Deploy to EKS
      run: |
        aws eks update-kubeconfig --name production-cluster
        kubectl set image deployment/myapp container=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        kubectl rollout status deployment/myapp

# 3. Jenkins Pipeline Security
// Jenkinsfile
pipeline {
    agent any
    
    options {
        // Security options
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        skipStagesAfterUnstable()
    }
    
    environment {
        VAULT_ADDR = 'https://vault.company.com'
        VAULT_NAMESPACE = 'production'
        SONAR_HOST = 'https://sonarqube.company.com'
    }
    
    stages {
        stage('Security Scan') {
            parallel {
                stage('SAST') {
                    steps {
                        script {
                            def scanResult = sh(
                                script: 'sonar-scanner -Dsonar.projectKey=myapp -Dsonar.sources=.',
                                returnStatus: true
                            )
                            if (scanResult != 0) {
                                error("SAST scan failed with critical issues")
                            }
                        }
                    }
                }
                
                stage('Dependency Check') {
                    steps {
                        sh 'safety check --json --output safety-report.json'
                        sh 'npm audit --audit-level high'
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: '.',
                            reportFiles: 'safety-report.json',
                            reportName: 'Security Report'
                        ])
                    }
                }
            }
        }
        
        stage('Secure Build') {
            steps {
                script {
                    // Retrieve secrets from Vault
                    withVault([
                        configuration: [
                            vaultUrl: env.VAULT_ADDR,
                            vaultCredentialId: 'vault-approle'
                        ],
                        vaultSecrets: [
                            [
                                path: 'secret/data/myapp',
                                secretValues: [
                                    [envVar: 'DB_PASSWORD', vaultKey: 'db_password'],
                                    [envVar: 'API_KEY', vaultKey: 'api_key']
                                ]
                            ]
                        ]
                    ]) {
                        // Build with secrets
                        sh 'docker build --build-arg DB_PASSWORD=$DB_PASSWORD -t myapp:${BUILD_NUMBER} .'
                        
                        // Sign the image
                        sh 'cosign sign --key /vault/secrets/signing-key myapp:${BUILD_NUMBER}'
                    }
                }
            }
        }
        
        stage('Security Testing') {
            steps {
                // Container scanning
                sh 'trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:${BUILD_NUMBER}'
                
                // DAST scanning
                sh '''
                    docker run --rm -v $(pwd):/zap/wrk/:rw \
                    -t owasp/zap2docker-weekly zap-baseline.py \
                    -t https://staging.example.com \
                    -J zap-report.json
                '''
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'zap-report.json',
                        reportName: 'DAST Report'
                    ])
                }
            }
        }
    }
    
    post {
        failure {
            emailext (
                subject: "Security Pipeline Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security issues detected in pipeline. Check console output for details.",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

### 14. Secrets Management in Pipelines

**Scenario**: Your CI/CD pipeline needs access to various secrets for different environments without exposing them.

**Solution**:
```yaml
# 1. HashiCorp Vault Integration
# vault-policy.hcl
path "secret/data/myapp/dev/*" {
  capabilities = ["read"]
}

path "secret/data/myapp/prod/*" {
  capabilities = ["read"]
  # Additional controls for production
  allowed_parameters = {
    "version" = []
  }
  min_wrapping_ttl = "1h"
  max_wrapping_ttl = "24h"
}

# Vault AppRole authentication
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

resource "vault_approle_auth_backend_role" "ci_cd" {
  backend        = vault_auth_backend.approle.path
  role_name      = "ci-cd-pipeline"
  token_policies = ["ci-cd-policy"]
  
  token_ttl     = 1800
  token_max_ttl = 3600
  
  # Security constraints
  bind_secret_id = true
  secret_id_ttl  = 3600
}

# 2. Kubernetes External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-secret-store
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        appRole:
          path: "approle"
          roleId: "ci-cd-role-id"
          secretRef:
            name: vault-secret-id
            key: secret-id

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 15m
  secretStoreRef:
    name: vault-secret-store
    kind: SecretStore
  target:
    name: myapp-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: myapp/prod
      property: db_password
  - secretKey: api-key
    remoteRef:
      key: myapp/prod
      property: api_key

# 3. AWS Secrets Manager with rotation
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "myapp/production/database"
  description             = "Database credentials for production"
  recovery_window_in_days = 7
  
  replica {
    region = "us-west-2"
  }
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    username = "app_user"
    password = random_password.db_password.result
  })
}

# Automatic rotation
resource "aws_secretsmanager_secret_rotation" "app_secrets" {
  secret_id           = aws_secretsmanager_secret.app_secrets.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
  
  rotation_rules {
    automatically_after_days = 30
  }
}

# 4. Docker secrets management
# docker-compose.yml for local development
version: '3.8'
services:
  app:
    image: myapp:latest
    secrets:
      - db_password
      - api_key
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true

# Create secrets using external tools
# docker secret create db_password - < /dev/stdin
# echo "secret_value" | docker secret create api_key -

# 5. Azure DevOps with Key Vault
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
- group: production-secrets  # Variable group linked to Key Vault

stages:
- stage: SecurityValidation
  jobs:
  - job: SecurityScan
    steps:
    - task: AzureKeyVault@2
      inputs:
        azureSubscription: 'production-service-connection'
        KeyVaultName: 'prod-keyvault'
        SecretsFilter: 'database-password,api-key'
        RunAsPreJob: true
    
    - script: |
        # Use secrets from Key Vault (available as pipeline variables)
        echo "Connecting to database..."
        # Database password is now available as $(database-password)
      displayName: 'Secure Database Connection'
      env:
        DB_PASSWORD: $(database-password)
        API_KEY: $(api-key)

- stage: Deploy
  dependsOn: SecurityValidation
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: DeployToProduction
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: Kubernetes@1
            inputs:
              connectionType: 'Azure Resource Manager'
              azureSubscriptionEndpoint: 'production-service-connection'
              azureResourceGroup: 'production-rg'
              kubernetesCluster: 'production-aks'
              command: 'apply'
              arguments: '-f k8s/production/'
```

## Advanced Kubernetes Security Solutions

### 15. Pod Security Standards Implementation

**Scenario**: You need to enforce that no containers run as root and all must use read-only root filesystems across the cluster.

**Solution**:
```yaml
# 1. Pod Security Standards with admission controllers
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# 2. Security Context Constraints (OpenShift) or Pod Security Policy
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true

---
# 3. Gatekeeper/OPA policies for enforcement
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        type: object
        properties:
          runAsNonRoot:
            type: boolean
          readOnlyRootFilesystem:
            type: boolean
          allowedCapabilities:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsecuritycontext
        
        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            not container.securityContext.runAsNonRoot
            msg := "Container must run as non-root user"
        }
        
        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            not container.securityContext.readOnlyRootFilesystem
            msg := "Container must use read-only root filesystem"
        }
        
        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            has_disallowed_capabilities(container)
            msg := "Container uses disallowed capabilities"
        }
        
        has_disallowed_capabilities(container) {
            capability := container.securityContext.capabilities.add[_]
            not capability in input.parameters.allowedCapabilities
        }

---
# Apply the constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: must-run-as-non-root
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]
  parameters:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
    allowedCapabilities: []

# 4. Compliant deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      serviceAccountName: secure-app-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: cache-volume
          mountPath: /app/cache
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
      volumes:
      - name: tmp-volume
        emptyDir:
          sizeLimit: "1Gi"
      - name: cache-volume
        emptyDir:
          sizeLimit: "512Mi"

---
# 5. Network policies for microsegmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-app-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: secure-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-ingress
    - namespaceSelector:
        matchLabels:
          name: ingress-system
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to: []  # DNS
    ports:
    - protocol: UDP
      port: 53
  - to: []  # HTTPS for external APIs
    ports:
    - protocol: TCP
      port: 443
```

## Complex Multi-Cloud Scenarios & Solutions

### 16. Multi-Cloud Disaster Recovery

**Scenario**: Design a disaster recovery solution with RPO of 1 hour and RTO of 4 hours for a critical application across AWS and Azure.

**Solution**:
```hcl
# 1. Terraform configuration for multi-cloud DR
# AWS Primary Region
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}

provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
}

provider "azurerm" {
  alias = "dr"
  features {}
}

# Primary AWS infrastructure
module "aws_primary" {
  source = "./modules/aws-infrastructure"
  
  providers = {
    aws = aws.primary
  }
  
  environment = "production"
  region      = "us-east-1"
  
  # Database with cross-region replication
  enable_cross_region_backup = true
  backup_retention_period    = 7
  
  # S3 with cross-region replication
  enable_cross_region_replication = true
  destination_bucket_region       = "us-west-2"
}

# AWS Secondary Region (Hot Standby)
module "aws_secondary" {
  source = "./modules/aws-infrastructure"
  
  providers = {
    aws = aws.secondary
  }
  
  environment = "dr-standby"
  region      = "us-west-2"
  
  # Reduced capacity for cost optimization
  instance_count = 1
  instance_type  = "t3.medium"
  
  # Read replica setup
  create_read_replica = true
  primary_db_arn     = module.aws_primary.database_arn
}

# Azure DR Site (Cold Standby)
module "azure_dr" {
  source = "./modules/azure-infrastructure"
  
  providers = {
    azurerm = azurerm.dr
  }
  
  environment = "disaster-recovery"
  location    = "West Europe"
  
  # Minimal infrastructure for DR activation
  vm_count = 0  # Will be scaled up during DR
  
  # Storage replication from AWS
  enable_azure_site_recovery = true
  source_region              = "us-east-1"
}

# 2. Database replication and backup strategy
resource "aws_db_instance" "primary" {
  identifier = "myapp-primary"
  
  # Automated backups for point-in-time recovery
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  # Enable automated backups to S3
  copy_tags_to_snapshot = true
  
  # Cross-region automated backups
  manage_master_user_password = true
  
  tags = {
    Environment = "production"
    BackupType  = "automated"
  }
}

resource "aws_db_instance" "read_replica" {
  provider = aws.secondary
  
  identifier = "myapp-replica"
  
  # Create cross-region read replica
  replicate_source_db = aws_db_instance.primary.id
  
  # Can be promoted to standalone during DR
  auto_minor_version_upgrade = true
  
  tags = {
    Environment = "dr-standby"
    Purpose     = "disaster-recovery"
  }
}

# 3. Application-level DR automation
# Kubernetes disaster recovery configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: dr-automation-config
  namespace: kube-system
data:
  dr-script.sh: |
    #!/bin/bash
    
    # DR activation script
    DR_ACTIVATION_THRESHOLD=300  # 5 minutes of downtime
    
    function check_primary_health() {
        # Check primary site health
        curl -f --max-time 10 https://api.primary.example.com/health
        return $?
    }
    
    function activate_dr() {
        echo "Activating disaster recovery..."
        
        # 1. Promote read replica to primary
        aws rds promote-read-replica \
            --db-instance-identifier myapp-replica \
            --region us-west-2
        
        # 2. Update DNS to point to DR site
        aws route53 change-resource-record-sets \
            --hosted-zone-id Z123456789 \
            --change-batch file://dns-change.json
        
        # 3. Scale up Azure resources if needed
        az vmss scale \
            --resource-group dr-rg \
            --name app-vmss \
            --new-capacity 3
        
        # 4. Update load balancer configuration
        kubectl patch service frontend-service \
            -p '{"spec":{"selector":{"version":"dr"}}}'
        
        # 5. Notify stakeholders
        curl -X POST "https://hooks.slack.com/services/..." \
            -H 'Content-type: application/json' \
            --data '{"text":"DR activated for production environment"}'
    }
    
    # Continuous monitoring loop
    while true; do
        if ! check_primary_health; then
            sleep 30
            if ! check_primary_health; then
                echo "Primary site down, initiating DR..."
                activate_dr
                break
            fi
        fi
        sleep 60
    done

# 4. Data synchronization strategy
# Velero for Kubernetes backup and restore
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-config
data:
  velero-schedule.yaml: |
    apiVersion: velero.io/v1
    kind: Schedule
    metadata:
      name: production-backup
      namespace: velero
    spec:
      schedule: "0 */1 * * *"  # Every hour for RPO requirement
      template:
        includedNamespaces:
        - production
        - monitoring
        storageLocation: aws-s3-backup
        ttl: 720h0m0s  # 30 days retention
        hooks:
          resources:
          - name: database-consistent-backup
            includedNamespaces:
            - production
            labelSelector:
              matchLabels:
                app: database
            pre:
            - exec:
                container: postgres
                command:
                - /bin/bash
                - -c
                - "pg_start_backup('velero-backup')"
            post:
            - exec:
                container: postgres
                command:
                - /bin/bash
                - -c
                - "pg_stop_backup()"

# 5. Monitoring and alerting for DR
resource "aws_cloudwatch_alarm" "primary_site_health" {
  alarm_name          = "primary-site-health-check"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthCheck"
  namespace           = "AWS/Route53"
  period              = "60"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors primary site health"
  
  alarm_actions = [
    aws_sns_topic.dr_alerts.arn,
    aws_lambda_function.dr_automation.arn
  ]
  
  dimensions = {
    HealthCheckId = aws_route53_health_check.primary.id
  }
}

# Lambda function for automated DR
resource "aws_lambda_function" "dr_automation" {
  filename         = "dr-automation.zip"
  function_name    = "disaster-recovery-automation"
  role            = aws_iam_role.lambda_dr_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 300
  
  environment {
    variables = {
      SECONDARY_REGION = "us-west-2"
      AZURE_RESOURCE_GROUP = "dr-rg"
      NOTIFICATION_TOPIC = aws_sns_topic.dr_alerts.arn
    }
  }
}
```

### 17. Service Mesh Security with Istio

**Scenario**: You need to implement mTLS between all services in your cluster and enforce fine-grained access control.

**Solution**:
```yaml
# 1. Istio installation with security features
# istio-security-config.yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: production-istio
spec:
  values:
    pilot:
      env:
        EXTERNAL_ISTIOD: false
        PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION: true
    global:
      meshConfig:
        defaultConfig:
          proxyStatsMatcher:
            inclusionRegexps:
            - ".*circuit_breakers.*"
            - ".*upstream_rq_retry.*"
            - ".*_cx_.*"
        extensionProviders:
        - name: oauth2-proxy
          envoyOauth2:
            service: oauth2-proxy.istio-system.svc.cluster.local
            port: 4180
  components:
    pilot:
      k8s:
        env:
        - name: PILOT_ENABLE_CROSS_CLUSTER_WORKLOAD_ENTRY
          value: "true"

# 2. Strict mTLS enforcement
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT

---
# Per-service mTLS configuration
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: database-mtls
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  mtls:
    mode: STRICT
  portLevelMtls:
    5432:
      mode: STRICT

# 3. Authorization policies
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: frontend
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*"]
  - when:
    - key: source.ip
      values: ["10.0.0.0/8"]
    - key: request.headers[authorization]
      values: ["Bearer *"]

---
# Database access policy - highly restrictive
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: database-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/backend-service"]
  - to:
    - operation:
        ports: ["5432"]
  - when:
    - key: source.namespace
      values: ["production"]

# 4. JWT validation and external authorization
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  jwtRules:
  - issuer: "https://auth.company.com"
    jwksUri: "https://auth.company.com/.well-known/jwks.json"
    audiences:
    - "api.company.com"
    forwardOriginalToken: true

---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: jwt-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  rules:
  - from:
    - source:
        requestPrincipals: ["https://auth.company.com/user-123"]
  - when:
    - key: request.auth.claims[role]
      values: ["admin", "user"]
    - key: request.auth.claims[exp]
      values: ["*"]

# 5. External authorization with OPA
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: opa-external-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: sensitive-service
  action: CUSTOM
  provider:
    name: opa-ext-authz
  rules:
  - to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]

---
# OPA policy ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-policy
  namespace: istio-system
data:
  policy.rego: |
    package istio.authz
    
    import future.keywords.if
    import future.keywords.in
    
    default allow := false
    
    # Allow if user has admin role
    allow if {
        input.attributes.request.http.headers.authorization
        token := trim_prefix(input.attributes.request.http.headers.authorization, "Bearer ")
        payload := io.jwt.decode_verify(token, {"secret": "your-secret"})
        payload[2].role == "admin"
    }
    
    # Allow read operations for regular users during business hours
    allow if {
        input.attributes.request.http.method in ["GET"]
        time.now_ns() >= time.parse_rfc3339_ns("2024-01-01T09:00:00Z")
        time.now_ns() <= time.parse_rfc3339_ns("2024-01-01T17:00:00Z")
        token := trim_prefix(input.attributes.request.http.headers.authorization, "Bearer ")
        payload := io.jwt.decode_verify(token, {"secret": "your-secret"})
        payload[2].role == "user"
    }
    
    # Deny sensitive operations from untrusted networks
    allow if {
        not input.attributes.source.address in ["192.0.2.0/24", "203.0.113.0/24"]
        input.attributes.request.http.method in ["DELETE", "PUT"]
    }
```

### 18. Advanced AWS Lambda Security

**Scenario**: Secure Lambda functions handling sensitive data with proper IAM, VPC configuration, and monitoring.

**Solution**:
```python
# 1. Secure Lambda function code
import json
import boto3
import os
import logging
from datetime import datetime
import hmac
import hashlib

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients with least privilege
session = boto3.Session()
kms = session.client('kms')
secrets_manager = session.client('secretsmanager')
dynamodb = session.resource('dynamodb')

def lambda_handler(event, context):
    try:
        # Input validation and sanitization
        if not validate_input(event):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid input'})
            }
        
        # Verify request signature for additional security
        if not verify_signature(event):
            logger.warning(f"Invalid signature from IP: {event.get('requestContext', {}).get('identity', {}).get('sourceIp')}")
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Forbidden'})
            }
        
        # Retrieve secrets securely
        db_credentials = get_secret('prod/database/credentials')
        
        # Process data with encryption
        processed_data = process_sensitive_data(event['body'], db_credentials)
        
        # Audit logging
        audit_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': event.get('requestContext', {}).get('authorizer', {}).get('userId'),
            'action': 'data_processing',
            'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
            'user_agent': event.get('headers', {}).get('User-Agent', ''),
            'request_id': context.aws_request_id
        }
        logger.info(json.dumps(audit_log))
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
            },
            'body': json.dumps(processed_data)
        }
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

def validate_input(event):
    """Validate and sanitize input data"""
    required_fields = ['user_id', 'action', 'data']
    body = json.loads(event.get('body', '{}'))
    
    for field in required_fields:
        if field not in body:
            return False
    
    # Additional validation logic
    if len(body.get('data', '')) > 10000:  # Size limit
        return False
    
    return True

def verify_signature(event):
    """Verify HMAC signature for request authenticity"""
    secret = get_secret('prod/webhook/secret')
    signature = event.get('headers', {}).get('X-Signature-256', '')
    
    if not signature:
        return False
    
    expected_signature = hmac.new(
        secret.encode(),
        event.get('body', '').encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, f"sha256={expected_signature}")

def get_secret(secret_name):
    """Retrieve secret from AWS Secrets Manager with caching"""
    try:
        response = secrets_manager.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f"Failed to retrieve secret {secret_name}: {e}")
        raise

def process_sensitive_data(data, credentials):
    """Process data with encryption and secure handling"""
    # Encrypt sensitive data using KMS
    kms_key_id = os.environ['KMS_KEY_ID']
    
    encrypted_data = kms.encrypt(
        KeyId=kms_key_id,
        Plaintext=json.dumps(data)
    )
    
    # Store in DynamoDB with encryption at rest
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])
    
    table.put_item(
        Item={
            'id': context.aws_request_id,
            'encrypted_data': encrypted_data['CiphertextBlob'],
            'timestamp': datetime.utcnow().isoformat(),
            'ttl': int((datetime.utcnow().timestamp() + 86400))  # 24 hour TTL
        }
    )
    
    return {'status': 'processed', 'id': context.aws_request_id}

# 2. Terraform configuration for secure Lambda
resource "aws_lambda_function" "secure_processor" {
  filename         = "secure-processor.zip"
  function_name    = "secure-data-processor"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.lambda_handler"
  runtime         = "python3.9"
  timeout         = 30
  memory_size     = 512
  
  # VPC configuration for network isolation
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  # Environment variables (encrypted)
  environment {
    variables = {
      KMS_KEY_ID      = aws_kms_key.lambda_key.id
      DYNAMODB_TABLE  = aws_dynamodb_table.secure_data.name
      LOG_LEVEL       = "INFO"
    }
  }
  
  # Enable X-Ray tracing for monitoring
  tracing_config {
    mode = "Active"
  }
  
  # Reserved concurrency to prevent resource exhaustion
  reserved_concurrent_executions = 100
  
  tags = {
    Environment = "production"
    DataClass   = "sensitive"
  }
}

# Lambda execution role with least privilege
resource "aws_iam_role" "lambda_role" {
  name = "secure-lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "secure-lambda-policy"
  role = aws_iam_role.lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.lambda_key.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "lambda.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:prod/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.secure_data.arn
        Condition = {
          ForAllValues:StringEquals = {
            "dynamodb:Attributes" = ["id", "encrypted_data", "timestamp", "ttl"]
          }
        }
      }
    ]
  })
}

# 3. VPC and network security for Lambda
resource "aws_security_group" "lambda_sg" {
  name_prefix = "secure-lambda-"
  vpc_id      = var.vpc_id
  
  # No inbound rules - Lambda doesn't need them
  ingress = []
  
  # Outbound only to specific services
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HTTPS to AWS services
  }
  
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database_sg.id]
  }
  
  tags = {
    Name = "secure-lambda-sg"
  }
}

# 4. Lambda monitoring and alerting
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/secure-data-processor"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.lambda_key.arn
}

resource "aws_cloudwatch_metric_filter" "lambda_errors" {
  name           = "lambda-error-rate"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "ERROR"
  
  metric_transformation {
    name      = "LambdaErrors"
    namespace = "Production/Lambda"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "lambda_error_rate" {
  alarm_name          = "lambda-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "LambdaErrors"
  namespace           = "Production/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Lambda error rate is too high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# 5. Lambda@Edge for security at the edge
resource "aws_lambda_function" "security_headers" {
  filename         = "security-headers.zip"
  function_name    = "security-headers-edge"
  role            = aws_iam_role.lambda_edge_role.arn
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  publish         = true
  
  # Lambda@Edge specific configuration
  timeout = 5
  
  tags = {
    Purpose = "security-headers"
  }
}

# CloudFront distribution with Lambda@Edge
resource "aws_cloudfront_distribution" "secure_distribution" {
  origin {
    domain_name = aws_s3_bucket.content.bucket_domain_name
    origin_id   = "S3-secure-content"
    
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.main.cloudfront_access_identity_path
    }
  }
  
  default_cache_behavior {
    target_origin_id = "S3-secure-content"
    
    lambda_function_association {
      event_type   = "viewer-response"
      lambda_arn   = aws_lambda_function.security_headers.qualified_arn
      include_body = false
    }
    
    # Security settings
    viewer_protocol_policy = "redirect-to-https"
    compress              = true
    
    allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods  = ["GET", "HEAD"]
  }
  
  # Web Application Firewall
  web_acl_id = aws_wafv2_web_acl.security_acl.arn
  
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }
  
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.main.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# Lambda@Edge security headers function
# security-headers.js
exports.handler = async (event) => {
    const response = event.Records[0].cf.response;
    const headers = response.headers;
    
    // Add security headers
    headers['strict-transport-security'] = [{
        key: 'Strict-Transport-Security',
        value: 'max-age=63072000; includeSubDomains; preload'
    }];
    
    headers['content-security-policy'] = [{
        key: 'Content-Security-Policy',
        value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'"
    }];
    
    headers['x-content-type-options'] = [{
        key: 'X-Content-Type-Options',
        value: 'nosniff'
    }];
    
    headers['x-frame-options'] = [{
        key: 'X-Frame-Options',
        value: 'DENY'
    }];
    
    headers['x-xss-protection'] = [{
        key: 'X-XSS-Protection',
        value: '1; mode=block'
    }];
    
    headers['referrer-policy'] = [{
        key: 'Referrer-Policy',
        value: 'strict-origin-when-cross-origin'
    }];
    
    return response;
};
```

## Advanced Azure Security Solutions

### 19. Azure Sentinel SIEM Implementation

**Scenario**: Implement a comprehensive SIEM solution using Azure Sentinel for threat detection across your entire infrastructure.

**Solution**:
```powershell
# 1. Azure Sentinel deployment script
# deploy-sentinel.ps1

# Connect to Azure
Connect-AzAccount

# Create Log Analytics Workspace
$resourceGroup = "security-rg"
$workspaceName = "security-analytics-workspace"
$location = "East US"

$workspace = New-AzOperationalInsightsWorkspace `
    -ResourceGroupName $resourceGroup `
    -Name $workspaceName `
    -Location $location `
    -Sku "PerGB2018" `
    -RetentionInDays 90

# Enable Azure Sentinel
$sentinelSolution = @{
    Name = "SecurityInsights"
    Publisher = "Microsoft"
    Product = "OMSGallery/SecurityInsights"
    PromotionCode = ""
}

New-AzOperationalInsightsSolution @sentinelSolution `
    -ResourceGroupName $resourceGroup `
    -WorkspaceName $workspaceName

# 2. Data connectors configuration
# ARM template for data connectors
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspaceName": {
            "type": "string"
        }
    },
    "resources": [
        {
            "type": "Microsoft.OperationalInsights/workspaces/dataSources",
            "apiVersion": "2020-08-01",
            "name": "[concat(parameters('workspaceName'), '/AzureSecurityCenter')]",
            "kind": "AzureSecurityCenter",
            "properties": {
                "linkedResourceId": "[subscriptionResourceId('Microsoft.Security/autoProvisioningSettings', 'default')]"
            }
        },
        {
            "type": "Microsoft.OperationalInsights/workspaces/dataSources",
            "apiVersion": "2020-08-01",
            "name": "[concat(parameters('workspaceName'), '/Office365')]",
            "kind": "Office365",
            "properties": {
                "linkedResourceId": "[subscriptionResourceId('Microsoft.OfficeConsumption/directoryTenants', tenant().tenantId)]"
            }
        }
    ]
}

# 3. Custom analytics rules using KQL
# Create analytics rules via REST API
$headers = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type' = 'application/json'
}

# Suspicious login detection rule
$suspiciousLoginRule = @{
    kind = "Scheduled"
    properties = @{
        displayName = "Suspicious Login Patterns"
        description = "Detects suspicious login patterns including impossible travel"
        severity = "High"
        enabled = $true
        query = @"
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| extend LocationDetails = LocationDetails.countryOrRegion
| summarize 
    LoginCount = count(),
    Countries = make_set(LocationDetails),
    FirstLogin = min(TimeGenerated),
    LastLogin = max(TimeGenerated)
    by UserPrincipalName
| where array_length(Countries) > 1
| extend TimeDiff = datetime_diff('minute', LastLogin, FirstLogin)
| where TimeDiff < 120  // Impossible travel: multiple countries within 2 hours
| project 
    UserPrincipalName,
    SuspiciousActivity = "Impossible travel detected",
    Countries,
    TimeDifference = TimeDiff,
    FirstLogin,
    LastLogin
"@
        queryFrequency = "PT1H"
        queryPeriod = "PT1H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        suppressionDuration = "PT5H"
        suppressionEnabled = $false
        tactics = @("InitialAccess", "CredentialAccess")
        techniques = @("T1078", "T1110")
        entityMappings = @(
            @{
                entityType = "Account"
                fieldMappings = @(
                    @{
                        identifier = "FullName"
                        columnName = "UserPrincipalName"
                    }
                )
            }
        )
        incidentConfiguration = @{
            createIncident = $true
            groupingConfiguration = @{
                enabled = $true
                reopenClosedIncident = $false
                lookbackDuration = "PT5H"
                matchingMethod = "Selected"
                groupByEntities = @("Account")
            }
        }
    }
} | ConvertTo-Json -Depth 10

# 4. Custom hunting queries
# KQL queries for proactive threat hunting
$huntingQueries = @"
// 1. Detect privilege escalation attempts
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName contains "role assignment"
| where Result == "success"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResources = tostring(TargetResources[0].displayName)
| where InitiatedBy != TargetResources  // Self-assignment might be legitimate
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, AdditionalDetails

// 2. Detect data exfiltration patterns
StorageBlobLogs
| where TimeGenerated > ago(1h)
| where OperationName == "GetBlob"
| summarize 
    DownloadCount = count(),
    TotalBytes = sum(ResponseBodySize),
    UniqueBlobs = dcount(Uri)
    by CallerIpAddress, AuthenticatedUser = Identity
| where DownloadCount > 100 or TotalBytes > 1000000000  // 1GB threshold
| order by TotalBytes desc

// 3. Detect lateral movement
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624  // Successful logon
| where LogonType in (3, 10)  // Network or RDP logon
| summarize 
    LogonCount = count(),
    ComputerCount = dcount(Computer),
    Computers = make_set(Computer)
    by Account
| where ComputerCount > 5  // Accessing multiple systems
| order by ComputerCount desc

// 4. API abuse detection
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "ApplicationGatewayAccessLog"
| extend ClientIP = columnifexists("clientIP_s", "")
| extend ResponseCode = columnifexists("httpStatus_d", 0)
| summarize 
    RequestCount = count(),
    ErrorCount = countif(ResponseCode >= 400),
    ErrorRate = round(todouble(countif(ResponseCode >= 400)) / count() * 100, 2)
    by ClientIP
| where RequestCount > 1000 or ErrorRate > 50
| order by RequestCount desc
"@

# 5. Automated response playbooks
# Logic App for automated incident response
{
    "$schema": "https://schema.management.azure.com/schemas/2016-06-01/Microsoft.Logic.json",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "connections_azuresentinel_name": {
            "type": "String"
        }
    },
    "triggers": {
        "When_Azure_Sentinel_incident_creation_rule_was_triggered": {
            "type": "ApiConnectionWebhook",
            "inputs": {
                "host": {
                    "connection": {
                        "name": "@parameters('connections_azuresentinel_name')"
                    }
                },
                "body": {
                    "callback_url": "@{listCallbackUrl()}"
                },
                "path": "/incident-creation"
            }
        }
    },
    "actions": {
        "Check_Incident_Severity": {
            "type": "Switch",
            "expression": "@triggerBody()?['object']?['properties']?['severity']",
            "cases": {
                "High": {
                    "case": "High",
                    "actions": {
                        "Disable_Compromised_User": {
                            "type": "Http",
                            "inputs": {
                                "method": "PATCH",
                                "uri": "https://graph.microsoft.com/v1.0/users/@{triggerBody()?['object']?['properties']?['relatedEntities'][0]?['properties']?['aadUserId']}",
                                "headers": {
                                    "Authorization": "Bearer @{body('Get_Access_Token')?['access_token']}"
                                },
                                "body": {
                                    "accountEnabled": false
                                }
                            }
                        },
                        "Notify_Security_Team": {
                            "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://hooks.slack.com/services/...",
                                "body": {
                                    "text": "🚨 HIGH SEVERITY INCIDENT: @{triggerBody()?['object']?['properties']?['title']}\n\nUser automatically disabled: @{triggerBody()?['object']?['properties']?['relatedEntities'][0]?['properties']?['name']}\n\nIncident ID: @{triggerBody()?['object']?['name']}"
                                }
                            }
                        }
                    }
                },
                "Medium": {
                    "case": "Medium",
                    "actions": {
                        "Create_ServiceNow_Ticket": {
                            "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://company.service-now.com/api/now/table/incident",
                                "headers": {
                                    "Authorization": "Basic @{base64(concat(parameters('servicenow_user'), ':', parameters('servicenow_password')))}"
                                },
                                "body": {
                                    "short_description": "@{triggerBody()?['object']?['properties']?['title']}",
                                    "description": "@{triggerBody()?['object']?['properties']?['description']}",
                                    "priority": "2",
                                    "category": "Security"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

## Advanced Docker Security Solutions

### 20. Container Runtime Security with Falco

**Scenario**: Implement comprehensive runtime security monitoring for containers with automated response to threats.

**Solution**:
```yaml
# 1. Falco deployment with custom rules
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
  namespace: falco-system
data:
  falco.yaml: |
    rules_file:
      - /etc/falco/falco_rules.yaml
      - /etc/falco/falco_rules.local.yaml
      - /etc/falco/k8s_audit_rules.yaml
      - /etc/falco/rules.d
    
    time_format_iso_8601: true
    json_output: true
    json_include_output_property: true
    
    # Output channels
    file_output:
      enabled: true
      keep_alive: false
      filename: /var/log/falco/events.log
    
    stdout_output:
      enabled: true
    
    http_output:
      enabled: true
      url: "http://falco-exporter.falco-system.svc.cluster.local:9376/events"
    
    # gRPC output for real-time integrations
    grpc_output:
      enabled: true
      bind_address: "0.0.0.0:5060"
      threadiness: 8
    
    # Syscall event drops
    syscall_event_drops:
      actions:
        - log
        - alert
      rate: 0.1
      max_burst: 1000

  falco_rules.local.yaml: |
    # Custom rules for container security
    
    # Detect cryptocurrency mining
    - rule: Detect Cryptocurrency Mining
      desc: Detect cryptocurrency mining activities in containers
      condition: >
        spawned_process and container and
        (proc.name in (xmrig, ccminer, cgminer, bfgminer) or
         proc.cmdline contains "stratum+tcp" or
         proc.cmdline contains "mining pool" or
         proc.cmdline contains "cryptonight")
      output: >
        Cryptocurrency mining detected in container
        (user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
      priority: CRITICAL
      tags: [cryptocurrency, mining, malware]
    
    # Detect reverse shell attempts
    - rule: Reverse Shell in Container
      desc: Detect reverse shell connections from containers
      condition: >
        spawned_process and container and
        ((proc.name in (nc, ncat, netcat, socat) and
          (proc.cmdline contains "-e" or proc.cmdline contains "/bin/sh" or proc.cmdline contains "/bin/bash")) or
         (proc.name in (bash, sh) and proc.cmdline contains "/dev/tcp/"))
      output: >
        Reverse shell attempt detected in container
        (user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
      priority: CRITICAL
      tags: [shell, reverse_shell, attack]
    
    # Detect container escape attempts
    - rule: Container Escape Attempt
      desc: Detect attempts to escape container
      condition: >
        spawned_process and container and
        (proc.name in (docker, kubectl, crictl, runc, ctr) or
         fd.name contains "/var/run/docker.sock" or
         fd.name contains "/run/containerd" or
         proc.cmdline contains "CAP_SYS_ADMIN")
      output: >
        Container escape attempt detected
        (user=%user.name command=%proc.cmdline container=%container.name)
      priority: CRITICAL
      tags: [container_escape, privilege_escalation]
    
    # Detect suspicious file access
    - rule: Sensitive File Access in Container
      desc: Detect access to sensitive files
      condition: >
        open_read and container and
        (fd.name in (/etc/passwd, /etc/shadow, /etc/hosts, /etc/hostname, /proc/version, /etc/os-release) or
         fd.name startswith /proc/sys/ or
         fd.name startswith /sys/class/dmi/ or
         fd.name startswith /.aws/ or
         fd.name startswith /.azure/)
      output: >
        Sensitive file accessed in container
        (user=%user.name file=%fd.name container=%container.name command=%proc.cmdline)
      priority: WARNING
      tags: [file_access, sensitive_data]

---
# 2. Falco deployment
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco-system
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco-no-driver:latest
        securityContext:
          privileged: true
        args:
          - /usr/bin/falco
          - --cri=/run/containerd/containerd.sock
          - --k8s-api=https://kubernetes.default.svc.cluster.local
          - --k8s-api-cert=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          - --k8s-api-token=/var/run/secrets/kubernetes.io/serviceaccount/token
        volumeMounts:
        - mountPath: /host/var/run/docker.sock
          name: docker-socket
        - mountPath: /host/run/containerd
          name: containerd-socket
        - mountPath: /host/dev
          name: dev-fs
        - mountPath: /host/proc
          name: proc-fs
          readOnly: true
        - mountPath: /host/boot
          name: boot-fs
          readOnly: true
        - mountPath: /host/lib/modules
          name: lib-modules
        - mountPath: /host/usr
          name: usr-fs
          readOnly: true
        - mountPath: /host/etc
          name: etc-fs
          readOnly: true
        - mountPath: /etc/falco
          name: falco-config
      volumes:
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
      - name: containerd-socket
        hostPath:
          path: /run/containerd
      - name: dev-fs
        hostPath:
          path: /dev
      - name: proc-fs
        hostPath:
          path: /proc
      - name: boot-fs
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr-fs
        hostPath:
          path: /usr
      - name: etc-fs
        hostPath:
          path: /etc
      - name: falco-config
        configMap:
          name: falco-config

# 3. Automated response to Falco alerts
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falco-response
  namespace: falco-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: falco-response
  template:
    metadata:
      labels:
        app: falco-response
    spec:
      serviceAccountName: falco-response
      containers:
      - name: response-engine
        image: falco-response:latest
        env:
        - name: FALCO_GRPC_ENDPOINT
          value: "falco.falco-system.svc.cluster.local:5060"
        - name: SLACK_WEBHOOK_URL
          valueFrom:
            secretKeyRef:
              name: alert-secrets
              key: slack-webhook
        volumeMounts:
        - name: response-scripts
          mountPath: /scripts
      volumes:
      - name: response-scripts
        configMap:
          name: response-scripts
          defaultMode: 0755

---
# Response automation script
apiVersion: v1
kind: ConfigMap
metadata:
  name: response-scripts
  namespace: falco-system
data:
  response.py: |
    #!/usr/bin/env python3
    import grpc
    import json
    import requests
    import subprocess
    from kubernetes import client, config
    import falco_pb2
    import falco_pb2_grpc
    
    class FalcoResponseHandler:
        def __init__(self):
            # Initialize Kubernetes client
            config.load_incluster_config()
            self.k8s_client = client.ApiClient()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            
        def handle_alert(self, alert):
            """Process Falco alerts and take appropriate action"""
            try:
                alert_data = json.loads(alert.output)
                priority = alert_data.get('priority', 'INFO')
                rule = alert_data.get('rule', '')
                
                if priority == 'CRITICAL':
                    self.handle_critical_alert(alert_data)
                elif priority == 'HIGH':
                    self.handle_high_alert(alert_data)
                elif priority == 'WARNING':
                    self.handle_warning_alert(alert_data)
                    
            except Exception as e:
                print(f"Error handling alert: {e}")
        
        def handle_critical_alert(self, alert_data):
            """Handle critical security alerts"""
            container_name = alert_data.get('output_fields', {}).get('container.name')
            namespace = alert_data.get('output_fields', {}).get('k8s.ns.name', 'default')
            
            if container_name and 'cryptocurrency' in alert_data.get('rule', '').lower():
                # Immediately kill suspicious pod
                self.kill_pod(container_name, namespace)
                
            if 'reverse_shell' in alert_data.get('rule', '').lower():
                # Isolate the pod by updating network policies
                self.isolate_pod(container_name, namespace)
                
            # Send critical alert
            self.send_slack_alert(alert_data, "🚨 CRITICAL SECURITY ALERT")
        
        def handle_high_alert(self, alert_data):
            """Handle high priority alerts"""
            # Log to security system
            self.log_security_event(alert_data)
            
            # Send notification
            self.send_slack_alert(alert_data, "⚠️ HIGH PRIORITY ALERT")
        
        def kill_pod(self, container_name, namespace):
            """Forcefully terminate a suspicious pod"""
            try:
                pods = self.v1.list_namespaced_pod(namespace=namespace)
                for pod in pods.items:
                    if container_name in [c.name for c in pod.spec.containers]:
                        self.v1.delete_namespaced_pod(
                            name=pod.metadata.name,
                            namespace=namespace,
                            grace_period_seconds=0
                        )
                        print(f"Terminated suspicious pod: {pod.metadata.name}")
                        break
            except Exception as e:
                print(f"Failed to terminate pod: {e}")
        
        def isolate_pod(self, container_name, namespace):
            """Isolate pod using network policies"""
            isolation_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"isolate-{container_name}",
                    "namespace": namespace
                },
                "spec": {
                    "podSelector": {
                        "matchLabels": {
                            "security.falco.org/isolated": "true"
                        }
                    },
                    "policyTypes": ["Ingress", "Egress"]
                }
            }
            
            # Apply isolation policy
            self.k8s_client.create_namespaced_custom_object(
                group="networking.k8s.io",
                version="v1",
                namespace=namespace,
                plural="networkpolicies",
                body=isolation_policy
            )
        
        def send_slack_alert(self, alert_data, prefix):
            """Send alert to Slack"""
            webhook_url = os.getenv('SLACK_WEBHOOK_URL')
            if webhook_url:
                message = {
                    "text": f"{prefix}\n\nRule: {alert_data.get('rule')}\nContainer: {alert_data.get('output_fields', {}).get('container.name')}\nTime: {alert_data.get('time')}"
                }
                requests.post(webhook_url, json=message)
    
    def main():
        """Main function to start gRPC client"""
        handler = FalcoResponseHandler()
        
        # Connect to Falco gRPC server
        channel = grpc.insecure_channel('falco.falco-system.svc.cluster.local:5060')
        stub = falco_pb2_grpc.FalcoStub(channel)
        
        # Subscribe to alerts
        request = falco_pb2.Request()
        
        try:
            for response in stub.Subscribe(request):
                handler.handle_alert(response)
        except KeyboardInterrupt:
            print("Shutting down response handler")
    
    if __name__ == "__main__":
        main()
```

## Complete CI/CD Security Pipeline

### 21. End-to-End Secure Pipeline with Supply Chain Security

**Scenario**: Implement a complete secure CI/CD pipeline with supply chain security, including dependency verification, image signing, and deployment verification.

**Solution**:
```yaml
# 1. GitHub Actions with complete security pipeline
name: Secure Supply Chain Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-checks:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      id-token: write
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for better analysis
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    # Software Composition Analysis
    - name: Install dependencies
      run: npm ci --audit-signatures
    
    - name: Run npm audit
      run: |
        npm audit --audit-level=moderate --json > audit-report.json
        if [ $(cat audit-report.json | jq '.metadata.vulnerabilities.high + .metadata.vulnerabilities.critical') -gt 0 ]; then
          echo "High or critical vulnerabilities found"
          exit 1
        fi
    
    # License compliance check
    - name: License compliance
      run: |
        npx license-checker --summary --excludePrivatePackages > license-report.txt
        npx license-checker --failOn "GPL;AGPL;LGPL" --excludePrivatePackages
    
    # Static Application Security Testing (SAST)
    - name: Run Semgrep
      uses: semgrep/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/owasp-top-ten
          p/kubernetes
        generateSarif: "1"
    
    - name: Upload SARIF to GitHub
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: semgrep.sarif
    
    # Secret scanning
    - name: Run TruffleHog
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: main
        head: HEAD
        extra_args: --debug --only-verified

  build-and-sign:
    needs: security-checks
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
      image-url: ${{ steps.build.outputs.image-url }}
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Install Cosign
      uses: sigstore/cosign-installer@v3
    
    - name: Setup Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Login to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    # Build with attestations
    - name: Build and push image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: |
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
        cache-from: type=gha
        cache-to: type=gha,mode=max
        provenance: true
        sbom: true
    
    # Sign image with Sigstore
    - name: Sign image with Cosign
      run: |
        cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
    
    # Generate and sign SBOM
    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
        format: spdx-json
        output-file: sbom.spdx.json
    
    - name: Sign SBOM
      run: |
        cosign attest --yes --predicate sbom.spdx.json --type spdxjson ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}

  vulnerability-scan:
    needs: build-and-sign
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ needs.build-and-sign.outputs.image-url }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH,MEDIUM'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'
    
    # Fail if critical vulnerabilities found
    - name: Check vulnerability scan results
      run: |
        critical_count=$(cat trivy-results.sarif | jq '.runs[0].results | map(select(.level == "error")) | length')
        if [ "$critical_count" -gt 0 ]; then
          echo "Critical vulnerabilities found: $critical_count"
    