# Step 4.7: the verifier's identity on the API server and the key it signs
# NodeTrust updates with (blueprint 8.1).
#
# The client certificate (CN nodetrust-verifier, no groups) is signed by the
# cluster CA Terraform already holds; RBAC and a ValidatingAdmissionPolicy
# (infra/phase4/k8s/nodetrust.yaml) let only this user write NodeTrust
# objects. The signing key is separate from the TLS key: the trust
# controller (Phase 5) pins its public half and ignores any update it did
# not sign. Both private keys stay in Terraform state and reach the verifier
# host only through deploy-verifier.sh, as systemd credentials. Blueprint
# 10.7 future work: seal the signing key to a Nitro Enclave image with KMS.

resource "tls_private_key" "verifier_kube" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "verifier_kube" {
  private_key_pem = tls_private_key.verifier_kube.private_key_pem
  subject {
    common_name = "nodetrust-verifier"
  }
}

resource "tls_locally_signed_cert" "verifier_kube" {
  cert_request_pem      = tls_cert_request.verifier_kube.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 8760
  allowed_uses          = ["digital_signature", "client_auth"]
}

resource "tls_private_key" "nodetrust_signing" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

output "cluster_ca_pem" {
  description = "Cluster CA certificate (the verifier pins it for the API server)."
  value       = tls_self_signed_cert.ca.cert_pem
}

output "verifier_kube_cert_pem" {
  description = "The verifier's API client certificate (CN nodetrust-verifier)."
  value       = tls_locally_signed_cert.verifier_kube.cert_pem
}

output "verifier_kube_key_pem" {
  description = "Private key of the verifier's API client certificate."
  value       = tls_private_key.verifier_kube.private_key_pem
  sensitive   = true
}

output "nodetrust_signing_key_pem" {
  description = "Private key the verifier signs NodeTrust updates with."
  value       = tls_private_key.nodetrust_signing.private_key_pem
  sensitive   = true
}

output "nodetrust_signing_pub_pem" {
  description = "Public key of the NodeTrust signing key (the trust controller pins it)."
  value       = tls_private_key.nodetrust_signing.public_key_pem
}
