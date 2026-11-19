# Trust stack

Long-lived resources that must outlive any one cluster. Apply once and leave
it up; unlike infra/cluster it is not destroyed at the end of a session.

- S3 bucket nodetrust-manifests-<account>-<region>: versioned, private,
  encrypted, TLS only. Holds the reference manifests under
  manifests/<ami-id>/.
- IAM role and instance profile nodetrust-manifest-builder: SSM plus
  s3:PutObject under manifests/ only. No KMS access; signing is done off the
  builder.
- KMS key alias/nodetrust-manifest-signing (ECC_NIST_P256, sign/verify),
  with prevent_destroy: deleting it makes every signed manifest
  unverifiable. The private key never leaves KMS. Its public key is pinned
  in manifest-signing-key.pem here (written by sign-manifest.sh on first
  run).
- rekor-public-key.pem: the pinned key of the public Rekor log, written by
  infra/phase2/log-rekor.sh on first run. Commit it too.

```
cd infra/trust
terraform init
terraform apply
```

Cost: about USD 1 a month for the KMS key plus a few rupees for storage. Keep terraform.tfstate in this
folder; losing it means importing the bucket again.
