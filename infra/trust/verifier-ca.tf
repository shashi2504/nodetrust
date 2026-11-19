# --- verifier CA and client certificate (Phase 3, step 3.3) -------------------
# Agents accept requests only from a client certificate issued by this CA
# with the common name "nodetrust-verifier". The CA certificate is baked into
# the golden AMI (/etc/nodetrust/verifier-ca.pem), so it is covered by the
# signed manifest like any other file in the image.
#
# Phase 3 simplification: the CA and client keys live in this stack's
# Terraform state (local, not committed). Phase 4 moves the client key to the
# verifier host.

resource "tls_private_key" "verifier_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "verifier_ca" {
  private_key_pem       = tls_private_key.verifier_ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = 24 * 365 * 2
  allowed_uses          = ["cert_signing", "crl_signing"]
  subject {
    common_name  = "nodetrust verifier CA"
    organization = "nodetrust"
  }
}

resource "tls_private_key" "verifier_client" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "verifier_client" {
  private_key_pem = tls_private_key.verifier_client.private_key_pem
  subject {
    common_name  = "nodetrust-verifier"
    organization = "nodetrust"
  }
}

# Short-lived: Terraform replaces it on an apply in the last 7 days.
resource "tls_locally_signed_cert" "verifier_client" {
  cert_request_pem      = tls_cert_request.verifier_client.cert_request_pem
  ca_private_key_pem    = tls_private_key.verifier_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.verifier_ca.cert_pem
  validity_period_hours = 24 * 30
  early_renewal_hours   = 24 * 7
  allowed_uses          = ["digital_signature", "client_auth"]
}
