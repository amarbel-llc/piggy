package markl_registrations

import (
	"io"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
)

// makeStubPivyEcdhP256Format registers an erroring stub for the
// pivy_ecdh_p256_pub format. The real PIV-backed GetIOWrapper lives in
// go/markl/agent (dewey/pivy) and is injected over this stub via
// SwapFormat — keeping the dewey/pivy dep out of the markl core.
func makeStubPivyEcdhP256Format() {
	markl.RegisterFormat(markl.FormatSec{
		Id:   markl.FormatIdPivyEcdhP256Pub,
		Size: 33,
		GetIOWrapper: func(_ domain_interfaces.MarklId) (interfaces.IOWrapper, error) {
			return nil, errors.Wrap(markl.ErrPivyEcdhP256NotConnected)
		},
	})
}

// makeStubAgeX25519SecFormat registers an erroring stub for the
// age_x25519_sec format. The real age-backed Generate/GetIOWrapper live in
// go/markl/age (dewey/age) and are injected over this stub via SwapFormat —
// keeping the dewey/age dep out of the markl core.
func makeStubAgeX25519SecFormat() {
	markl.RegisterFormat(markl.FormatSec{
		Id:   markl.FormatIdAgeX25519Sec,
		Size: 32,
		Generate: func(_ io.Reader) ([]byte, error) {
			return nil, errors.Wrap(markl.ErrAgeX25519NotConnected)
		},
		GetIOWrapper: func(_ domain_interfaces.MarklId) (interfaces.IOWrapper, error) {
			return nil, errors.Wrap(markl.ErrAgeX25519NotConnected)
		},
	})
}
