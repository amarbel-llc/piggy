package markl

import (
	"crypto/ed25519"
	"fmt"

	"github.com/amarbel-llc/piggy/go/markl/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

// actual formats
const (
	// keep sorted
	FormatIdEd25519Pub = "ed25519_pub"
	FormatIdEd25519SSH = "ed25519_ssh"
	FormatIdEd25519Sec = "ed25519_sec"
	FormatIdEd25519Sig = "ed25519_sig"

	FormatIdAgeX25519Pub = "age_x25519_pub"
	FormatIdAgeX25519Sec = "age_x25519_sec"

	FormatIdEcdsaP256SSH = "ecdsa_p256_ssh"
	FormatIdEcdsaP256Pub = "ecdsa_p256_pub"
	FormatIdEcdsaP256Sig = "ecdsa_p256_sig"

	// SEC1-compressed P-256 public key (33 bytes), surfaced via the SSH
	// agent from a PIV authentication/signature slot (9A/9C/9E). Byte
	// shape is identical to ecdsa_p256_pub; the distinct format id lets a
	// purpose distinguish piggy PIV SSH-auth keys from recipient pubkeys
	// of the same shape. Owned jointly with amarbel-llc/piggy (mirrored
	// in its piggy-markl crate). See RFC 0002 §5.
	FormatIdSshEcdsaNistp256Pub = "ssh_ecdsa_nistp256_pub"

	FormatIdPivyEcdhP256Pub = "pivy_ecdh_p256_pub"

	FormatIdHashSha256     = "sha256"
	FormatIdHashBlake2b256 = "blake2b256"

	FormatIdNonceSec = "nonce"
)

// Format registrations are framework infrastructure (the actual crypto
// primitives), not consumer vocabulary, so they live in this package.
// Purpose registrations and purpose-id aliases moved out to
// internal/charlie/markl_registrations as of #106 step 2/3.
func init() {
	// Ed22519
	RegisterFormat(
		FormatPub{
			Id:     FormatIdEd25519Pub,
			Size:   ed25519.PublicKeySize,
			Verify: Ed25519Verify,
		},
	)

	RegisterFormat(
		FormatSec{
			Id:   FormatIdEd25519Sec,
			Size: ed25519.PrivateKeySize,

			Generate: Ed25519GeneratePrivateKey,

			PubFormatId:  FormatIdEd25519Pub,
			GetPublicKey: Ed25519GetPublicKey,

			SigFormatId: FormatIdEd25519Sig,
			Sign:        Ed25519Sign,
		},
	)

	RegisterFormat(
		Format{
			Id:   FormatIdEd25519Sig,
			Size: ed25519.SignatureSize,
		},
	)

	makeStubSSHFormat()

	// AgeX25519
	RegisterFormat(
		Format{
			Id:   FormatIdAgeX25519Pub,
			Size: 32,
		},
	)

	makeStubAgeX25519SecFormat()

	// ECDSA P256
	RegisterFormat(
		FormatPub{
			Id:     FormatIdEcdsaP256Pub,
			Size:   33,
			Verify: EcdsaP256Verify,
		},
	)

	RegisterFormat(
		Format{
			Id:   FormatIdEcdsaP256Sig,
			Size: 64,
		},
	)

	makeStubEcdsaP256SSHFormat()

	RegisterFormat(
		FormatPub{
			Id:     FormatIdSshEcdsaNistp256Pub,
			Size:   33,
			Verify: EcdsaP256Verify,
		},
	)

	// PivyEcdhP256
	makeStubPivyEcdhP256Format()

	// Nonce
	RegisterFormat(
		FormatSec{
			Id:       FormatIdNonceSec,
			Size:     32,
			Generate: NonceGenerate32,
		},
	)
}

var formats map[string]domain_interfaces.MarklFormat = map[string]domain_interfaces.MarklFormat{}

// SwapFormat replaces the registered format for id with f. The seam by
// which the go/markl/agent + go/markl/age sub-packages inject their real
// ssh/pivy/age-backed FormatSec over the erroring stub the core registered
// at init (the formats map is package-private). Closed-set: errors if no
// format is currently registered for id.
func SwapFormat(id string, f domain_interfaces.MarklFormat) error {
	if _, ok := formats[id]; !ok {
		return errors.Errorf("no format registered to swap: %q", id)
	}
	formats[id] = f
	return nil
}

// purposeIdToFormatIdAliases maps a purposeId-shaped string to a real
// formatId so legacy on-disk data carrying a purpose-id where a format-id
// is expected still resolves. Populated via RegisterPurposeIdAlias.
var purposeIdToFormatIdAliases = map[string]string{}

// RegisterPurposeIdAlias installs an alias from a purposeId-shaped string
// to a formatId. Panics on duplicate alias to match the registry's
// stability convention. The aliased formatId is not validated at
// registration time — GetFormatOrError surfaces an unknown target via its
// usual "unknown format id" error.
func RegisterPurposeIdAlias(purposeId, formatId string) {
	if existing, alreadyExists := purposeIdToFormatIdAliases[purposeId]; alreadyExists {
		panic(
			fmt.Sprintf(
				"purpose-id alias already registered: %q -> %q (attempted %q)",
				purposeId,
				existing,
				formatId,
			),
		)
	}

	purposeIdToFormatIdAliases[purposeId] = formatId
}

func GetFormatOrError(formatId string) (domain_interfaces.MarklFormat, error) {
	if aliased, ok := purposeIdToFormatIdAliases[formatId]; ok {
		formatId = aliased
	}

	format, ok := formats[formatId]

	if !ok {
		err := errors.Errorf("unknown format id: %q", formatId)
		return nil, err
	}

	return format, nil
}

// move to Id
func GetFormatSecOrError(
	formatIdGetter domain_interfaces.MarklFormatGetter,
) (formatSec FormatSec, err error) {
	format := formatIdGetter.GetMarklFormat()

	if format == nil {
		err = errors.Errorf("empty format for getter: %s", formatIdGetter)
		return formatSec, err
	}

	formatId := formatIdGetter.GetMarklFormat().GetMarklFormatId()

	if format, err = GetFormatOrError(formatId); err != nil {
		err = errors.Wrap(err)
		return formatSec, err
	}

	var ok bool

	if formatSec, ok = format.(FormatSec); !ok {
		err = errors.Errorf(
			"requested format is not FormatSec, but %T:%s",
			formatSec,
			formatId,
		)
		return formatSec, err
	}

	return formatSec, err
}

type FormatId string

func (formatId FormatId) GetMarklFormat() domain_interfaces.MarklFormat {
	format, err := GetFormatOrError(string(formatId))
	errors.PanicIfError(err)
	return format
}

type Format struct {
	Id   string
	Size int
}

var _ domain_interfaces.MarklFormat = Format{}

func (format Format) GetMarklFormatId() string {
	return format.Id
}

func (format Format) GetSize() int {
	return format.Size
}

// RegisterFormat installs a MarklFormat in the package-global registry.
// Panics on nil format, empty format id, or duplicate registration. Returns
// the registered format value so callers may keep a typed handle.
func RegisterFormat(format domain_interfaces.MarklFormat) domain_interfaces.MarklFormat {
	if format == nil {
		panic("nil format")
	}

	formatId := format.GetMarklFormatId()

	if formatId == "" {
		panic("empty formatId")
	}

	existing, alreadyExists := formats[formatId]

	if alreadyExists {
		panic(
			fmt.Sprintf(
				"format already registered: %q (%T)",
				formatId,
				existing,
			),
		)
	}

	formats[formatId] = format
	return format
}
