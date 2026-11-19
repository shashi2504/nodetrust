output "manifest_bucket" {
  value = aws_s3_bucket.manifests.id
}

output "builder_instance_profile" {
  value      = aws_iam_instance_profile.builder.name
  depends_on = [time_sleep.iam_propagation]
}

output "signing_key_arn" {
  value = aws_kms_key.manifest_signing.arn
}

output "verifier_ca_pem" {
  value = tls_self_signed_cert.verifier_ca.cert_pem
}

output "verifier_client_cert_pem" {
  value = tls_locally_signed_cert.verifier_client.cert_pem
}

output "verifier_client_key_pem" {
  value     = tls_private_key.verifier_client.private_key_pem
  sensitive = true
}
