# TPM layer (Phase 3 step 3.1)

Verifier side (pkg/attest, no TPM library): ParsePublic and CheckAK for
TPMT_PUBLIC, MakeCredential in software (RSA-OAEP or ECDH seed, KDFa,
AES-CFB, outer HMAC), ParseQuote and VerifyQuote (signature, TPM_GENERATED,
nonce, exact PCR set, PCR digest; returns the TPM reset count).

Agent side (pkg/agent): EK from the TCG RSA-2048 template and a restricted
ECDSA P-256 AK, both primary keys, so the same keys come back on every load
and nothing is stored on disk. ActivateCredential satisfies the EK policy
with PolicySecret(endorsement). Quote covers SHA-256 PCRs 0-10 and rereads
the PCRs around the quote so the values match it even while IMA extends PCR 10.

Checks:
- pkg/attest against go-tpm as an independent implementation: KDFa/KDFe,
  marshalling of the EK and AK templates (byte-identical), go-tpm's
  CreateCredential opened by our inverse, a go-tpm-marshalled quote verified
- pkg/agent against a real TPM implementation (make test-sim): the TPM's
  ActivateCredential opens attest.MakeCredential output, refuses it for
  another object name and when tampered; quotes pass attest.VerifyQuote and
  fail with another nonce or stale PCR values. Also run against swtpm
  (libtpms), a second TPM implementation, during development.
