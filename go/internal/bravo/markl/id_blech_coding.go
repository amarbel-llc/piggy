package markl

import (
	"encoding/hex"
	"strings"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"code.linenisgreat.com/piggy/go/internal/alfa/blech32"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

// TODO remove
func SetMaybeSha256(id domain_interfaces.MarklIdMutable, value string) (err error) {
	// TODO use registered format lengths
	switch len(value) {
	case 65:
		if value[0] != '@' {
			err = errors.Errorf("unknown format: %q", value)
			return err
		}

		value = strings.TrimPrefix(value, "@")
		fallthrough

	case 64:
		if err = setSha256(id, value); err != nil {
			err = errors.Wrap(err)
			return err
		}

	default:
		if err = id.Set(value); err != nil {
			err = errors.Wrap(err)
			return err
		}
	}

	return err
}

func SetMarklIdWithFormatBlech32(
	id domain_interfaces.MarklIdMutable,
	purposeId string,
	blechValue string,
) (err error) {
	if err = id.SetPurposeId(purposeId); err != nil {
		err = errors.Wrap(err)
		return err
	}

	// Legacy dodder box_format wire form prefixes purposeless markl-ID
	// tokens with `@` to distinguish them from other tokens (type tags
	// `!type`, etc.). The canonical RFC 0002 form has no leading `@`,
	// so strip it before handing off to id.Set — otherwise blech32
	// computes its checksum against HRP=`@<algo>` while the encoder
	// wrote with HRP=`<algo>`, the verification fails, and the dispatch
	// below misroutes through setSha256's hex.Decode (which then chokes
	// on the `@`). Closes amarbel-llc/madder#157.
	blechValue = strings.TrimPrefix(blechValue, "@")

	if err = id.Set(
		blechValue,
	); errors.Is(err, blech32.ErrSeparatorMissing) {
		if err = setSha256(
			id,
			blechValue,
		); err != nil {
			err = errors.Wrap(err)
			return err
		}
	} else if err != nil {
		err = errors.Wrap(err)
		return err
	}

	formatId := id.GetMarklFormat().GetMarklFormatId()

	if err = validatePurposeAndFormatId(purposeId, formatId); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func validatePurposeAndFormatId(purposeId string, formatId string) (err error) {
	if formatId == "" || purposeId == "" {
		return err
	}

	// Unknown purposes are carried opaquely (madder#255): decode surfaces
	// need only the format to route bytes, and downstream consumers mint
	// purposes this binary has no registration for. The compatibility
	// check applies only to registered purposes; semantic lookups
	// (GetPurpose, GetRelated) stay strict.
	purpose, registered := purposes[purposeId]
	if !registered {
		return err
	}

	if _, ok := purpose.formatIds[formatId]; !ok {
		err = errors.Errorf("format id %q not supported for purpose %q", formatId, purposeId)
		return err
	}

	return err
}

// TODO remove
func setSha256(id domain_interfaces.MarklIdMutable, value string) (err error) {
	var decodedBytes []byte

	if decodedBytes, err = hex.DecodeString(value); err != nil {
		err = errors.Wrapf(err, "%q", value)
		return err
	}

	if err = id.SetMarklId(
		FormatIdHashSha256,
		decodedBytes,
	); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}
