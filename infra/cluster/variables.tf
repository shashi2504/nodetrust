variable "region" {
  description = "AWS region."
  type        = string
  default     = "ap-south-1"
}

variable "cluster_name" {
  description = "Name used for resources and tags."
  type        = string
  default     = "nodetrust"
}

variable "worker_ami" {
  description = "Golden worker AMI from infra/phase1/ami/build-golden-ami.sh (UEFI, NitroTPM, Secure Boot, IMA)."
  type        = string
}

variable "controlplane_ami" {
  description = "AMI for the control plane and verifier hosts. Defaults to the golden worker AMI, which already has kubeadm."
  type        = string
  default     = null
}

variable "worker_instance_type" {
  description = "Worker instance type. Must support NitroTPM."
  type        = string
  default     = "m6i.large"
}

variable "worker_count" {
  description = "Number of workers in the Auto Scaling group."
  type        = number
  default     = 2
}

variable "controlplane_instance_type" {
  description = "Control plane instance type (kubeadm needs 2 vCPU)."
  type        = string
  default     = "t3.medium"
}

variable "verifier_instance_type" {
  description = "Verifier host instance type."
  type        = string
  default     = "t3.small"
}

variable "availability_zone" {
  description = "Single AZ for the whole cluster. Defaults to the first available AZ."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "VPC CIDR. Subnets are carved out of it in network.tf."
  type        = string
  default     = "10.42.0.0/16"
}

variable "pod_cidr" {
  description = "Calico pod CIDR. Must not overlap the VPC."
  type        = string
  default     = "192.168.0.0/16"
}

variable "calico_version" {
  description = "Calico release used for the tigera-operator manifest."
  type        = string
  default     = "v3.32.4" # v3.30 predates Kubernetes 1.35 and left the operator Degraded
}

variable "agent_port" {
  description = "TCP port the attestation agent listens on (Phase 3). Only the verifier may reach it."
  type        = number
  default     = 9443
}

variable "max_instance_lifetime" {
  description = "Seconds before the ASG replaces a worker with a fresh one from the golden AMI (blueprint 10.8). Minimum 86400."
  type        = number
  default     = 604800

  validation {
    condition     = var.max_instance_lifetime == 0 || var.max_instance_lifetime >= 86400
    error_message = "max_instance_lifetime must be 0 (off) or at least 86400 seconds."
  }
}

variable "tcp_established_timeout" {
  description = "ENI idle timeout in seconds for tracked TCP connections (blueprint 6.5). 60 is the minimum."
  type        = number
  default     = 60

  validation {
    condition     = var.tcp_established_timeout >= 60 && var.tcp_established_timeout <= 432000
    error_message = "tcp_established_timeout must be between 60 and 432000 seconds."
  }
}

variable "manifest_bucket" {
  description = "Bucket with the signed AMI manifests (infra/trust output manifest_bucket). The verifier role may read manifests/* and signed/* in it. Empty: no S3 access."
  type        = string
  default     = ""
}
