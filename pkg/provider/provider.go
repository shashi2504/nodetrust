// Package provider defines the two cloud-specific seams of nodetrust.
//
// Everything else in the framework (quote checks, IMA replay, scoring, drift)
// is cloud-neutral because TPM 2.0 and IMA are standards. Only two things
// depend on the cloud:
//
//   - EndorsementProvider: where the verifier gets a trustworthy copy of an
//     instance's TPM Endorsement Key (EK). The answer must come from the cloud
//     control plane, never from the instance itself.
//   - ContainmentProvider: how a compromised instance is isolated, preserved
//     for forensics, replaced and finally terminated, without any cooperation
//     from the instance.
//
// The AWS implementation lives in pkg/provider/aws (Phase 5). Every
// implementation must pass the suites in pkg/provider/conformance.
package provider

import (
	"context"
	"crypto"
	"errors"
)

// InstanceID identifies a worker in the cloud provider, for example an EC2
// instance ID such as "i-0123456789abcdef0".
type InstanceID string

// SnapshotID identifies one evidence snapshot (for AWS, an EBS snapshot ID).
type SnapshotID string

// EKKeyType selects which endorsement key to ask for.
type EKKeyType string

const (
	// EKRSA2048 is the RSA 2048-bit endorsement key.
	EKRSA2048 EKKeyType = "rsa-2048"
	// EKECCP384 is the ECC NIST P-384 endorsement key.
	EKECCP384 EKKeyType = "ecc-sec-p384"
)

// Errors every implementation must return (wrapped is fine; callers use errors.Is).
var (
	// ErrNotFound means the instance does not exist in the provider.
	ErrNotFound = errors.New("provider: instance not found")
	// ErrUnsupported means the request is valid but the provider cannot serve it,
	// for example an EK key type the platform does not offer.
	ErrUnsupported = errors.New("provider: unsupported")
	// ErrPrecondition means a containment step was called out of order,
	// for example Terminate before evidence was preserved.
	ErrPrecondition = errors.New("provider: precondition not met")
)

// EndorsementProvider returns the EK public key that the cloud provider
// reports for an instance. The verifier compares it with the EK the agent
// presents during enrollment, then uses credential activation to prove the
// agent's attestation key lives in that same TPM.
//
// Contract (checked by conformance.RunEndorsement):
//   - The key returned equals the EK in the instance's TPM.
//   - An unknown instance returns ErrNotFound.
//   - A key type the platform does not offer returns ErrUnsupported.
//   - A cancelled context returns an error and no key.
type EndorsementProvider interface {
	EKPublic(ctx context.Context, id InstanceID, kt EKKeyType) (crypto.PublicKey, error)
}

// ContainmentProvider carries out the out-of-band steps of the critical path
// (blueprint Section 8.3). None of these steps may depend on the instance's
// own kubelet, CNI or operating system.
//
// The steps have a fixed order:
//
//	Isolate -> Snapshot -> Replace -> Terminate
//
// Contract (checked by conformance.RunContainment):
//   - Every method is idempotent. Repeating a call that already succeeded
//     returns nil and does not repeat the effect; Snapshot returns the same
//     IDs as the first successful call.
//   - An unknown instance returns ErrNotFound.
//   - Replace before Isolate, and Terminate before Snapshot, return
//     ErrPrecondition, so capacity is never swapped while the node is still
//     on the network and evidence is never destroyed before it is preserved.
//   - After Terminate, Isolate, Snapshot and Replace return ErrPrecondition.
//   - A cancelled context returns an error and changes nothing.
type ContainmentProvider interface {
	// Isolate cuts the instance off the network: quarantine security group,
	// NACL deny for its addresses, or the provider's equivalent.
	Isolate(ctx context.Context, id InstanceID) error
	// Snapshot preserves the instance's disks for forensics and tags them
	// with the reason.
	Snapshot(ctx context.Context, id InstanceID, reason string) ([]SnapshotID, error)
	// Replace asks the instance group to launch a clean replacement while the
	// isolated instance keeps running.
	Replace(ctx context.Context, id InstanceID) error
	// Terminate destroys the instance. The controller calls it only after a
	// signed operator approval.
	Terminate(ctx context.Context, id InstanceID) error
	// State reports how far containment has progressed.
	State(ctx context.Context, id InstanceID) (State, error)
}

// State is the containment progress of one instance.
type State struct {
	Isolated   bool
	Snapshots  []SnapshotID
	Replaced   bool
	Terminated bool
}
