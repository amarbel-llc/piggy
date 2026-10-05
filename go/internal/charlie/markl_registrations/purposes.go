package markl_registrations

import (
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// Piggy's own canonical purpose registrations. Per piggy#183 (the markl-id
// ownership inversion), go/markl registers only PIGGY's purposes; every
// other domain (madder, dodder, papi, …) registers its own consumer-side
// against this framework (ADR 0006). Activated by blank-importing this
// package. Each var is exposed so consumers can introspect or template.
var (
	// piggy-piv_* — public keys from the PIV auth / signature / card-auth
	// slots (9A / 9C / 9E), carried as SSH-suitable points: P-256 (33-byte
	// compressed), Ed25519 (32-byte raw), or P-384 (49-byte compressed).
	// The Ed25519 + P-384 forms are piggy#86 (madder's Go core had only
	// the P-256 form).
	PurposePiggyPivAuthV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePiggyPivAuthV1,
		Type: markl.PurposeTypePubKey,
		FormatIds: []string{
			markl.FormatIdSshEcdsaNistp256Pub,
			markl.FormatIdSshEd25519Pub,
			markl.FormatIdSshEcdsaNistp384Pub,
		},
	}

	PurposePiggyPivSigV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePiggyPivSigV1,
		Type: markl.PurposeTypePubKey,
		FormatIds: []string{
			markl.FormatIdSshEcdsaNistp256Pub,
			markl.FormatIdSshEd25519Pub,
			markl.FormatIdSshEcdsaNistp384Pub,
		},
	}

	PurposePiggyPivCardAuthV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePiggyPivCardAuthV1,
		Type: markl.PurposeTypePubKey,
		FormatIds: []string{
			markl.FormatIdSshEcdsaNistp256Pub,
			markl.FormatIdSshEd25519Pub,
			markl.FormatIdSshEcdsaNistp384Pub,
		},
	}

	// piggy-recipient-v1 — the encryption recipient pubkey (PIV slot 9D
	// ECDH key, or an age recipient) piggy encrypts blobs to.
	PurposePiggyRecipientV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePiggyRecipientV1,
		Type: markl.PurposeTypePubKey,
		FormatIds: []string{
			markl.FormatIdPivyEcdhP256Pub,
			markl.FormatIdAgeX25519Pub,
		},
	}

	// pigpen-wrap-v1 — a sealed pigpen document's per-recipient wrapped
	// file key (piggy RFC 0008 §2.4, §5).
	PurposePigpenWrapV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePigpenWrapV1,
		Type: markl.PurposeTypePigpenWrap,
		FormatIds: []string{
			markl.FormatIdPigpenWrapP256,
			markl.FormatIdPigpenWrapX25519,
		},
	}

	// pigpen-doc-v1 — a sealed pigpen document's header MAC, or the
	// content digest of its `@`-referenced payload (piggy RFC 0008 §5).
	PurposePigpenDocV1Opts = markl.RegisterPurposeOpts{
		Id:   markl.PurposePigpenDocV1,
		Type: markl.PurposeTypePigpenDoc,
		FormatIds: []string{
			markl.FormatIdPigpenHeaderMac,
			markl.FormatIdHashBlake2b256,
		},
	}
)

// AllPurposes is the ordered list of piggy's own purpose registrations.
// Order is deterministic but consumers must not depend on it — registration
// is order-independent under markl's lazy Related validation (ADR 0006).
var AllPurposes = []markl.RegisterPurposeOpts{
	PurposePiggyPivAuthV1Opts,
	PurposePiggyPivSigV1Opts,
	PurposePiggyPivCardAuthV1Opts,
	PurposePiggyRecipientV1Opts,
	PurposePigpenWrapV1Opts,
	PurposePigpenDocV1Opts,
}

func init() {
	for _, opts := range AllPurposes {
		markl.RegisterPurpose(opts)
	}
}
