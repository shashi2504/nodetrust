# Instance roles. Every host gets SSM (the only way in). Workers get nothing
# else: no EC2, IAM or KMS permissions (blueprint Section 4). The verifier may
# read EKs and describe instances for enrollment, and read the signed AMI
# manifests (Phase 4). It cannot write to the bucket or sign anything.

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host" {
  for_each           = toset(["controlplane", "workers", "verifier"])
  name               = "${var.cluster_name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  for_each   = aws_iam_role.host
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  for_each = aws_iam_role.host
  name     = each.value.name
  role     = each.value.name
}

data "aws_iam_policy_document" "verifier" {
  statement {
    sid       = "Enrollment"
    actions   = ["ec2:GetInstanceTpmEkPub", "ec2:DescribeInstances"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = var.manifest_bucket == "" ? [] : [var.manifest_bucket]
    content {
      sid     = "ReadSignedManifests"
      actions = ["s3:GetObject"]
      resources = [
        "arn:aws:s3:::${statement.value}/manifests/*",
        "arn:aws:s3:::${statement.value}/signed/*",
      ]
    }
  }
}

resource "aws_iam_role_policy" "verifier" {
  name   = "enrollment"
  role   = aws_iam_role.host["verifier"].id
  policy = data.aws_iam_policy_document.verifier.json
}

# New instance profiles take a few seconds to propagate. Without this wait the
# Auto Scaling group's first launch can fail with "Authentication Failure"
# (seen on the first apply, 2026-11-15) even though a retry later succeeds.
resource "time_sleep" "iam_propagation" {
  create_duration = "20s"
  depends_on = [
    aws_iam_instance_profile.host,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.verifier,
  ]
}
