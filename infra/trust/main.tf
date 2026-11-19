# Long-lived trust stack. Unlike infra/cluster, this stays up between
# sessions: it holds the signed reference manifests (and, from step 2.2, the
# signing key), which must outlive any one cluster.

data "aws_caller_identity" "this" {}

locals {
  bucket = "nodetrust-manifests-${data.aws_caller_identity.this.account_id}-${var.region}"
}

# --- manifest bucket ---------------------------------------------------------

resource "aws_s3_bucket" "manifests" {
  bucket = local.bucket
}

resource "aws_s3_bucket_versioning" "manifests" {
  bucket = aws_s3_bucket.manifests.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "manifests" {
  bucket                  = aws_s3_bucket.manifests.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "manifests" {
  bucket = aws_s3_bucket.manifests.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "manifests" {
  bucket = aws_s3_bucket.manifests.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "manifests_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.manifests.arn,
      "${aws_s3_bucket.manifests.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "manifests" {
  bucket     = aws_s3_bucket.manifests.id
  policy     = data.aws_iam_policy_document.manifests_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.manifests]
}

# --- manifest builder role ---------------------------------------------------
# The throwaway builder instance reads a volume made from the golden AMI's
# snapshot and uploads the unsigned manifest. It can only write under
# manifests/ and has no KMS access: signing happens off the builder (step 2.2).

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "builder" {
  name               = "nodetrust-manifest-builder"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "builder_ssm" {
  role       = aws_iam_role.builder.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "builder_put" {
  statement {
    sid       = "PutUnsignedManifests"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.manifests.arn}/manifests/*"]
  }
}

resource "aws_iam_role_policy" "builder_put" {
  name   = "put-manifests"
  role   = aws_iam_role.builder.id
  policy = data.aws_iam_policy_document.builder_put.json
}

resource "aws_iam_instance_profile" "builder" {
  name = "nodetrust-manifest-builder"
  role = aws_iam_role.builder.name
}

# New instance profiles take a few seconds to become usable by run-instances.
resource "time_sleep" "iam_propagation" {
  create_duration = "20s"
  depends_on = [
    aws_iam_instance_profile.builder,
    aws_iam_role_policy_attachment.builder_ssm,
    aws_iam_role_policy.builder_put,
  ]
}

# --- manifest signing key (step 2.2) -----------------------------------------
# Asymmetric ECDSA P-256 key. The private half never leaves KMS; the signer
# (your laptop, later CI) calls kms:Sign on the statement digest, and the
# verifier is given only the public key, pinned in manifest-signing-key.pem.
# No key policy is set, so the account's IAM policies decide who may sign;
# the builder role has no KMS permissions at all.

resource "aws_kms_key" "manifest_signing" {
  description              = "nodetrust reference manifest signing (ECDSA P-256)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30

  # Destroying the key makes every signed manifest unverifiable.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "manifest_signing" {
  name          = "alias/nodetrust-manifest-signing"
  target_key_id = aws_kms_key.manifest_signing.key_id
}
