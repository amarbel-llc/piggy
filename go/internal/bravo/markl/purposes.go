package markl

import (
	"fmt"
	"unicode"
)

// purposes currently treated as formats
const (
	// TODO move to ids' builtin types
	// and then add registration
	// keep sorted

	// Blob Digests
	PurposeBlobDigestV1 = "dodder-blob-digest-sha256-v1"

	// Blob-Store-Config Digests
	PurposeBlobStoreConfigDigestV1 = "madder-blob_store-config-digest-v1"

	// Object Digests
	PurposeObjectDigestV1             = "dodder-object-digest-sha256-v1"
	PurposeObjectDigestV2             = "dodder-object-digest-v2"
	PurposeObjectDigestV3             = "dodder-object-digest-v3"
	PurposeV5MetadataDigestWithoutTai = "dodder-object-metadata-digest-without_tai-v1"

	// Object Mother Sigs
	PurposeObjectMotherSigV1 = "dodder-object-mother-sig-v1"
	PurposeObjectMotherSigV2 = "dodder-object-mother-sig-v2"
	PurposeObjectMotherSigV3 = "dodder-object-mother-sig-v3"

	// Object Sigs
	PurposeObjectSigV0 = "dodder-repo-sig-v1"
	PurposeObjectSigV1 = "dodder-object-sig-v1"
	PurposeObjectSigV2 = "dodder-object-sig-v2"
	PurposeObjectSigV3 = "dodder-object-sig-v3"

	// Request Auth
	PurposeRequestAuthResponseV1  = "dodder-request_auth-response-v1"
	PurposeRequestRepoSigV1       = "dodder-request_auth-repo-sig-v1"
	PurposeRequestAuthChallengeV1 = "dodder-request_auth-challenge-v1"

	// PubKeys
	PurposeRepoPubKeyV1   = "dodder-repo-public_key-v1"
	PurposeMadderPubKeyV1 = "madder-public_key-v1"

	// PrivateKeys
	PurposeRepoPrivateKeyV1   = "dodder-repo-private_key-v1"
	PurposeMadderPrivateKeyV0 = "madder-private_key-v0"
	PurposeMadderPrivateKeyV1 = "madder-private_key-v1"

	// Piggy keys (jointly owned with amarbel-llc/piggy; see RFC 0002 §6.1
	// and the piggy-markl crate). The piggy-piv_* purposes carry a PIV
	// slot's SSH-suitable public key; piggy-recipient-v1 carries an
	// encryption recipient pubkey (PIV slot 9D or an age recipient).
	// keep sorted
	PurposePiggyPivAuthV1     = "piggy-piv_auth-v1"      // PIV slot 9A
	PurposePiggyPivCardAuthV1 = "piggy-piv_card_auth-v1" // PIV slot 9E
	PurposePiggyPivSigV1      = "piggy-piv_sig-v1"       // PIV slot 9C
	PurposePiggyRecipientV1   = "piggy-recipient-v1"     // PIV slot 9D / age

	// Papi signature purposes (jointly owned with amarbel-llc/papi; RFC
	// 0002 §6.1, RFC-0001 §9–§10). Both carry a slot-9A ECDSA-P256
	// (ecdsa-sha2-nistp256) signature as the 64-byte r‖s payload once
	// SSH-wire framing is stripped, registered under PurposeTypePapiSig:
	//   papi-doc-sig-v1   — over a PAPI document's canonicalized (JCS)
	//                       bytes (§10.2).
	//   papi-proof-sig-v1 — over a PAPI identity-proof claim string
	//                       (§9.3 fmt="signature").
	//
	// MOVE-DOWN (piggy#186): papi is a DOWNSTREAM consumer of piggy's
	// markl. These purposes live here transitionally (piggy is the
	// canonical holder + joint owner); once papi depends on piggy's
	// published markl module they move down to papi, which registers its
	// own purposes consumer-side via RegisterPurpose (ADR 0006). The wire
	// strings stay stable across the move.
	// keep sorted
	PurposePapiDocSigV1   = "papi-doc-sig-v1"
	PurposePapiProofSigV1 = "papi-proof-sig-v1"
)

// Production registrations live in internal/charlie/markl_registrations
// (or any other consumer-side package). The constants above are the
// vocabulary; the registrations are the data. Keeping the data outside
// this framework package is the load-bearing change for #106 — a
// downstream consumer can install its own purposes via
// markl.RegisterPurpose without forking this package. See ADR 0006.

var purposes = map[string]Purpose{}

// validatePurposeCharset enforces RFC 0002 §2.1's `purpose-char` grammar:
// a purpose admits any Unicode code point except the literal `@` (the
// purpose/digest join rune) and whitespace (a bare markl-id text form has
// no quoting mechanism to represent it, per §2.2). This is the sole
// structural constraint shared by every purpose — registered or general
// (piggy#219); registered purposes additionally get the narrower
// `system-domain-role-version` naming convention enforced at
// registration time (RegisterPurpose callers), and their compatible-format
// constraint (validatePurposeAndFormatId). General/unregistered purposes
// get no further validation beyond this charset.
func validatePurposeCharset(purposeId string) error {
	for _, r := range purposeId {
		if r == '@' || unicode.IsSpace(r) {
			return ErrInvalidPurposeCharset{PurposeId: purposeId, Rune: r}
		}
	}

	return nil
}

type Purpose struct {
	id        string
	tipe      PurposeType
	formatIds map[string]struct{}
	related   map[string]string
}

func GetPurpose(purposeId string) Purpose {
	purpose, ok := purposes[purposeId]

	if !ok {
		panic(fmt.Sprintf("no purpose registered for id %q", purposeId))
	}

	return purpose
}

// RegisterPurposeOpts is the public registration shape for purposes.
//
// Related is a free-form role → purposeId map (see ADR 0006). Values are
// validated lazily: lookups via Purpose.GetRelated succeed for any registered
// role, and a downstream caller passing the result to GetPurpose is what
// surfaces typos.
type RegisterPurposeOpts struct {
	Id        string
	Type      PurposeType
	FormatIds []string
	Related   map[string]string
}

// RegisterPurpose installs a Purpose in the package-global registry. Panics
// if Id is already registered, or if FormatIds contains a duplicate. Returns
// the constructed Purpose so callers may keep a typed handle.
func RegisterPurpose(opts RegisterPurposeOpts) Purpose {
	if _, alreadyExists := purposes[opts.Id]; alreadyExists {
		panic(fmt.Sprintf("purpose already registered: %q", opts.Id))
	}

	purpose := Purpose{
		id:        opts.Id,
		tipe:      opts.Type,
		formatIds: make(map[string]struct{}, len(opts.FormatIds)),
		related:   make(map[string]string, len(opts.Related)),
	}

	for _, formatId := range opts.FormatIds {
		if _, ok := purpose.formatIds[formatId]; ok {
			panic(
				fmt.Sprintf(
					"format id (%q) registered for purpose (%q) more than once",
					formatId,
					opts.Id,
				),
			)
		}

		purpose.formatIds[formatId] = struct{}{}
	}

	for role, relatedId := range opts.Related {
		purpose.related[role] = relatedId
	}

	purposes[opts.Id] = purpose
	return purpose
}

func (purpose Purpose) GetPurposeType() PurposeType {
	return purpose.tipe
}

// GetRelated looks up a related purposeId by role. Returns ("", false) if
// no purpose was registered under that role for this Purpose. The returned
// purposeId is not validated against the registry — pass it to GetPurpose
// to resolve.
func (purpose Purpose) GetRelated(role string) (string, bool) {
	relatedId, ok := purpose.related[role]
	return relatedId, ok
}

// Role names used by madder's own purposes. Other consumers may define
// their own role constants — markl itself stays role-agnostic per ADR
// 0006. RelatedRolePublicKey is consulted by Id.GetPublicKey to find a
// private-key purpose's paired public-key purpose; without it, the
// method has no way to stamp the result.
const (
	RelatedRoleDigest    = "digest"
	RelatedRoleMotherSig = "mother_sig"
	RelatedRolePublicKey = "public_key"
)

func GetDigestTypeForSigType(sigId string) string {
	sig := GetPurpose(sigId)

	digestId, ok := sig.GetRelated(RelatedRoleDigest)
	if !ok {
		panic(fmt.Sprintf("unsupported sig purpose: %q", sigId))
	}

	return digestId
}

func GetMotherSigTypeForSigType(sigId string) string {
	sig := GetPurpose(sigId)

	motherSigId, ok := sig.GetRelated(RelatedRoleMotherSig)
	if !ok {
		panic(fmt.Sprintf("unsupported sig purpose: %q", sigId))
	}

	return motherSigId
}
