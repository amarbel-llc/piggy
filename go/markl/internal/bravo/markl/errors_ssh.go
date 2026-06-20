package markl

import (
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

var ErrEd25519SSHAgentNotConnected, IsErrEd25519SSHAgentNotConnected = errors.MakeTypedSentinel[pkgErrDisamb](
	"ed25519 SSH agent signer not connected",
)

var ErrPivyEcdhP256NotConnected, IsErrPivyEcdhP256NotConnected = errors.MakeTypedSentinel[pkgErrDisamb](
	"pivy ECDH p256 agent not connected",
)

var ErrAgeX25519NotConnected, IsErrAgeX25519NotConnected = errors.MakeTypedSentinel[pkgErrDisamb](
	"age x25519 identity not connected",
)
