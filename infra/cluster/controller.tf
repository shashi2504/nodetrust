# Phase 5: the trust controller runs on the control plane host and uses that
# host's IAM role for the critical path (blueprint 8.3). Workers have none of
# these permissions.
#
# - an API client certificate, CN nodetrust-controller, signed by the
#   cluster CA (RBAC in infra/phase5/k8s/controller.yaml)
# - the quarantine security group: no rules at all (Terraform removes the
#   default allow-all egress rule), so a node moved into it can open no new
#   connection and accept none
# - IAM: describe, swap security groups, add ACL denies, snapshot, tag,
#   detach from the Auto Scaling group, and terminate (only by an operator's
#   "controller terminate"). The mutating EC2 calls are limited to this
#   VPC's resources where AWS supports a condition on it.

resource "tls_private_key" "controller_kube" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "controller_kube" {
  private_key_pem = tls_private_key.controller_kube.private_key_pem
  subject {
    common_name = "nodetrust-controller"
  }
}

resource "tls_locally_signed_cert" "controller_kube" {
  cert_request_pem      = tls_cert_request.controller_kube.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 8760
  allowed_uses          = ["digital_signature", "client_auth"]
}

resource "aws_security_group" "quarantine" {
  name        = "${var.cluster_name}-quarantine"
  description = "nodetrust quarantine: no inbound, no outbound"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.cluster_name}-quarantine" }
}

data "aws_iam_policy_document" "controller" {
  statement {
    sid = "Read"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeSnapshots",
      "autoscaling:DescribeAutoScalingInstances",
    ]
    resources = ["*"]
  }
  statement {
    sid     = "Quarantine"
    actions = ["ec2:ModifyNetworkInterfaceAttribute", "ec2:CreateNetworkAclEntry"]
    resources = [
      "arn:aws:ec2:${var.region}:*:network-interface/*",
      "arn:aws:ec2:${var.region}:*:security-group/${aws_security_group.quarantine.id}",
      "arn:aws:ec2:${var.region}:*:network-acl/${aws_network_acl.infra.id}",
      "arn:aws:ec2:${var.region}:*:vpc/${aws_vpc.this.id}",
    ]
  }
  statement {
    sid       = "Evidence"
    actions   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
    resources = ["*"]
  }
  statement {
    sid       = "Replace"
    actions   = ["autoscaling:DetachInstances"]
    resources = [aws_autoscaling_group.workers.arn]
  }
  statement {
    sid       = "TerminateQuarantined"
    actions   = ["ec2:TerminateInstances"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/nodetrust:containment"
      values   = ["isolated", "snapshotted", "replaced"]
    }
  }
}

resource "aws_iam_role_policy" "controller" {
  name   = "trust-controller"
  role   = aws_iam_role.host["controlplane"].id
  policy = data.aws_iam_policy_document.controller.json
}

output "controller_kube_cert_pem" {
  description = "The trust controller's API client certificate (CN nodetrust-controller)."
  value       = tls_locally_signed_cert.controller_kube.cert_pem
}

output "controller_kube_key_pem" {
  description = "Private key of the trust controller's API client certificate."
  value       = tls_private_key.controller_kube.private_key_pem
  sensitive   = true
}

output "quarantine_sg_id" {
  description = "Empty security group the controller moves a critical node into."
  value       = aws_security_group.quarantine.id
}

output "quarantine_nacl_id" {
  description = "Network ACL of the public, control plane and verifier subnets (controller quarantine denies)."
  value       = aws_network_acl.infra.id
}
