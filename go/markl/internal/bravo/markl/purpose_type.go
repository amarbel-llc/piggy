// Package markl is piggy's canonical markl-id registry — the purpose and
// format vocabularies, the Id codec, and the format registry. Under
// piggy#183 (the markl-id ownership inversion) this is the source of
// truth; madder drops its own copy and depends on piggy's pkgs/ facade.
package markl

//go:generate dagnabit export

type PurposeType interface {
	purposeType()
}

type purposeType byte

var _ PurposeType = purposeType(0)

func (purposeType) purposeType() {}

const (
	PurposeTypeUnknown = purposeType(iota)
	PurposeTypeBlobDigest
	PurposeTypeObjectDigest
	PurposeTypeObjectMotherSig
	// PurposeTypeDodderObjectSig was madder's PurposeTypeObjectSig; renamed
	// under piggy#183 since its purpose VALUES are dodder-specific
	// (dodder-object-sig-v2). Label-only — nothing branches on the byte.
	PurposeTypeDodderObjectSig
	PurposeTypePrivateKey
	PurposeTypePubKey
	PurposeTypeRepoPubKey
	PurposeTypeRequestAuth
	// PurposeTypePapiSig — the amarbel-llc/papi signature purposes
	// (papi-doc-sig-v1, papi-proof-sig-v1). Distinct from the dodder
	// object-sig type per Sasha's taxonomy ruling (#183). madder's
	// papi-doc-sig-v1 landed under ObjectSig; piggy, as the canonical
	// holder, overrides it to this dedicated type. Transitional — moves
	// down to papi with the papi purposes (#186).
	PurposeTypePapiSig
)
