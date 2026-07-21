package markl

import (
	"bytes"
	"fmt"

	"code.linenisgreat.com/piggy/go/internal/alfa/blech32"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
)

// MarshalText writes the RFC 0002 §3 wire form
// `[purpose@]<blech32(format, data)>`. The blech32 checksum binds to
// (format, data) only; the purpose, when present, is prepended
// textually after blech32 encoding so the same digest under different
// purposes shares a byte-identical blech32 body.
func (id Id) MarshalText() (bites []byte, err error) {
	if id.format == nil {
		return bites, err
	}

	if bites, err = blech32.Encode(id.format.GetMarklFormatId(), id.data); err != nil {
		err = errors.Wrap(err)
		return bites, err
	}

	if purpose := id.GetPurposeId(); purpose != "" {
		// spellPurpose quotes when the value falls outside RFC 0011
		// §2.1's bare inclusion set (madder#273 rulings 1 and 2). This
		// is a second marshal path alongside Id.StringWithFormat; both
		// must spell the slot the same way or a value would round-trip
		// through one and not the other.
		bites = []byte(fmt.Sprintf("%s@%s", spellPurpose(purpose), string(bites)))
	}

	return bites, err
}

// UnmarshalText parses the RFC 0002 §4 wire form. The purpose, when
// present, is split off textually before blech32 decoding so the
// checksum verifies against HRP=format only.
func (id *Id) UnmarshalText(bites []byte) (err error) {
	if len(bites) == 0 {
		id.Reset()
		return err
	}

	body := bites

	// splitPurposeSlot is quote-aware: §2.2 permits a QUOTED purpose to
	// contain '@' (piggy#227), so the join is not simply the first one
	// and a bytes.IndexByte scan would slice `"a@b"@fmt-data` in half.
	// SetPurposeFromWireSlot is then the chokepoint that unquotes and
	// validates as one step. This is a second wire-parse path alongside
	// Id.Set — sharing both helpers is what keeps the two from drifting.
	if slot, rest, hasPurpose := splitPurposeSlot(string(bites)); hasPurpose {
		if err = id.SetPurposeFromWireSlot(slot); err != nil {
			err = errors.Wrapf(err, "Raw: %q", string(bites))
			return err
		}

		body = []byte(rest)
	}

	var formatId string
	var data []byte

	if formatId, data, err = blech32.Decode(body); err != nil {
		if purpose := id.GetPurposeId(); purpose != "" &&
			errors.Is(err, blech32.ErrInvalidChecksum) {
			if legacy, ok := buildLegacyCombinedHRPError(
				purpose, bites, body,
			); ok {
				return legacy
			}
		}
		err = errors.Wrapf(err, "Raw: %q", string(bites))
		return err
	}

	if err = id.SetMarklId(formatId, data); err != nil {
		err = errors.Wrapf(err, "Raw: %q", string(bites))
		return err
	}

	return err
}

// buildLegacyCombinedHRPError returns a populated
// ErrLegacyCombinedHRPWireForm when `body` verifies under the legacy
// combined `<purpose>@<format>` HRP. The `bites` argument carries the
// full original input (including the purpose prefix) for the Raw
// field; `body` is the post-`@` section that DecodeWithHRPOverride
// inspects.
func buildLegacyCombinedHRPError(
	purpose string,
	bites []byte,
	body []byte,
) (ErrLegacyCombinedHRPWireForm, bool) {
	sep := bytes.LastIndexByte(body, '-')
	if sep <= 0 {
		return ErrLegacyCombinedHRPWireForm{}, false
	}

	combinedHRP := purpose + "@" + string(body[:sep])

	innerHRP, data, ok := blech32.DecodeWithHRPOverride(combinedHRP, body)
	if !ok {
		return ErrLegacyCombinedHRPWireForm{}, false
	}

	// Canonical split-HRP form re-encodes (innerHRP, data); only the
	// trailing 6-char checksum differs from the legacy body, so
	// surface just that suffix for splice-style migration callers.
	canonical, encErr := blech32.Encode(innerHRP, data)
	if encErr != nil || len(canonical) < 6 {
		return ErrLegacyCombinedHRPWireForm{}, false
	}

	return ErrLegacyCombinedHRPWireForm{
		Purpose:          purpose,
		FormatId:         innerHRP,
		Data:             data,
		SplitHRPChecksum: string(canonical[len(canonical)-6:]),
		Raw:              string(bites),
	}, true
}
