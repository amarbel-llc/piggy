package blech32

import (
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

// TODO make generic
type Value struct {
	HRP  string // human-readable part
	Data []byte
}

func MakeValue(
	hrp string,
	data []byte,
) Value {
	return Value{
		HRP:  hrp,
		Data: data,
	}
}

func MakeValueWithExpectedHRP(
	expectedHRP string,
	input string,
) (value Value, err error) {
	if err = value.Set(input); err != nil {
		err = errors.Wrap(err)
		return value, err
	}

	if value.HRP != expectedHRP {
		err = errors.Errorf(
			"expected HRP %q but got %q",
			expectedHRP,
			value.HRP,
		)
		return value, err
	}

	return value, err
}

func (value Value) GetHRP() string {
	return value.HRP
}

func (value Value) GetData() []byte {
	return value.Data
}

func (value Value) String() string {
	var text []byte
	var err error

	if text, err = Encode(value.HRP, value.Data); err != nil {
		panic(errors.Wrap(err))
	}

	return string(text)
}

func (value *Value) Set(text string) (err error) {
	if len(text) == 0 {
		return err
	}

	if value.HRP, value.Data, err = DecodeString(text); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func (value Value) MarshalText() (text []byte, err error) {
	if len(value.Data) == 0 {
		return text, err
	}

	if text, err = Encode(value.HRP, value.Data); err != nil {
		err = errors.Wrap(err)
		return text, err
	}

	return text, err
}

func (value *Value) UnmarshalText(text []byte) (err error) {
	if len(text) == 0 {
		return err
	}

	if value.HRP, value.Data, err = DecodeString(string(text)); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

// NOTE (piggy #183 port): madder's blech32.Value carried a
// WriteToMerkleId(domain_interfaces.MarklIdMutable) convenience method —
// a back-reference from the low-level codec UP to the markl Id
// interface. That is the reverse of the dewey -> piggy -> madder
// layering (the codec must not depend on the Id type), and it imported
// madder's internal/0/domain_interfaces (a madder-internal package, not
// importable from piggy). Dropped here; the Value -> Id conversion lives
// on the Id side in go/markl core. Confirm the seam with madder when the
// core lands.
