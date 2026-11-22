piggy-piv-slots(7)

# NAME

piggy-piv-slots - PIV slot conventions for piggy and the wider YubiKey ecosystem

# DESCRIPTION

This page documents PIV slot usage as it pertains to piggy: which slot
piggy uses today, what NIST SP 800-73 says about each slot, what Yubico
permits in practice on YubiKey hardware, and what other ecosystem tools
(*pivy*, *age-plugin-yubikey*) do with the so-called *retired Key
Management* slots. It exists to give contributors a single reference
for the trade-offs involved in expanding piggy's slot support beyond
slot 9D.

# PIV SLOT MAP

NIST SP 800-73 (the PIV card command interface spec) defines four
named key slots plus a range of retired Key Management slots:

[[ *Slot*
:[ *NIST role*
:[ *Typical use*
|  9A
:  PIV Authentication
:  signature-only (login, ssh-with-piv)
|  9C
:  Digital Signature
:  document/email signing
|  9D
:  Key Management
:  ECDH key agreement (encrypt / decrypt)
|  9E
:  Card Authentication
:  contactless card-presence proof
|  82h-95h
:  Retired Key Management
:  archive of rotated 9D keys (20 slots)
|  F9
:  Attestation (Yubico extension)
:  on-card attestation of generated keys

Slot 9D is the only slot whose NIST-sanctioned role is encryption.
Slots 9A/9C/9E are signature-only and cannot perform the ECDH operation
that *pivy-box* needs to unwrap an ebox.

# RETIRED KEY MANAGEMENT SLOTS

## NIST intent

Per NIST SP 800-73-4 Part 1, slots 82h-95h are reserved for *retired*
Key Management keys, so that a cardholder can still decrypt data
encrypted to a previously rotated 9D key after rotation.

The verbatim normative text was *not* retrieved from the primary PDF
during research; the slot range and naming are documented secondhand
via Yubico's slot reference (cited below). Treat the "retired" framing
as Yubico-secondhand pending a direct read of NIST SP 800-73-4. The
spec landing page is at
_https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final_.

## YubiKey policy

Yubico explicitly permits general-purpose use of these slots on YubiKey
4 and 5 hardware. From
_https://developers.yubico.com/PIV/Introduction/Certificate_slots.html_:

```
These slots are only available on the YubiKey 4 & 5. They are meant
for previously used Key Management keys to be able to decrypt
earlier encrypted documents or emails. In the YubiKey 4 & 5 all 20
of them are fully available for use.
```

YubiKey firmware does not enforce the "retired" semantic; the slots
behave as ordinary Key Management slots.

## Ecosystem practice

*age-plugin-yubikey* (_https://github.com/str4d/age-plugin-yubikey_)
generates new, *active* age recipients in retired slots, not in 9D.
From its README, "Manual setup and technical details" section:

```
any PIV token with an ECDSA P-256 key and certificate in one of the
20 "retired" slots should work
```

*pivy* (_https://github.com/arekinath/pivy_), the upstream of piggy's
crypto layer, recommends retired slots for any imported (non-attested)
key. From its README, "Setting up a new YubiKey" section:

```
these slots can be used for anything you like... If you need to
import an existing key into your YubiKey, I would recommend using
one of these retired slots rather than placing it in one of the
"main 4".
```

The de-facto convention on YubiKey hardware is therefore: use 9A/9C/9D/9E
for the four named PIV roles, and use 82h-95h as a pool of 20
general-purpose Key Management slots.

# USAGE IN PIGGY

*piggy pass init* delegates template creation to *pivy-box tpl create*.
With *local-guid <guid>*, *pivy-box* defaults to slot *9D* (Key
Management / ECDH), which is the only NIST-sanctioned encryption slot
on a PIV card. piggy does not currently expose a flag to choose a
different slot; non-9D slot selection requires the *-i* (interactive)
mode, which hands control to *pivy-box*'s interactive template builder.

piggy reads and writes the retired slots as ordinary key slots:

- Card enumeration reads the certificate of every slot 82h-95h that has
  one, so *piggy list* and *piggy-agent*(1) see their keys alongside
  9A/9C/9D/9E (the agent's slot filter can exclude them).
- *piggy tool pubkey*, *cert*, *attest* and *sign* accept any slot that
  holds a certificate, retired slots included; *piggy tool
  update-keyhist* counts the retired slots that hold one.
- *piggy tool generate*, *import*, *write-cert*, *req-cert*,
  *delete-cert* and *ecdh* take 9A/9C/9D/9E and 82h-95h, and refuse F9
  and every other id. *generate*'s *-i* and *-t* set a retired-slot
  key's PIN and touch policy as they do for a named slot.
- *piggy pass recipients list-available* treats 82h-95h, like 9D, as
  recipient-eligible; see *piggy*(1).

# CERTIFICATE AUTHORITY SLOTS

Two retired slots hold a certificate authority's key. Each is a
*kind*, and each kind may certify one thing only; the card agent
(*piggy-agent*(1)), *piggy tool sign* and *piggy ca* all read the kind from
one place and refuse the wrong request before the card is touched or a
prompt is shown.

[[ *Slot*
:[ *Name*
:[ *Certifies*
|  82
:  retired-1
:  X.509 certificates, through *piggy ca* only (FDR 0007)
|  83
:  retired-2
:  OpenSSH user certificates, through the agent (*ssh-keygen -U -s*)

A CA key is generated on the card with PIN always and touch always, for
example:

```
piggy tool -K @store -a eccp256 -i always -t always generate 83
```

*piggy tool generate* on slot 82 or 83 with no *-i* or *-t* generates PIN
always and touch always (the card's own default, PIN once and touch never,
is not one the agent signs with). The agent reads the key's ATTESTATION on
every request and signs nothing with a CA slot's key that the card does not
attest as generated on it with PIN always and touch always: an imported key,
or one generated with a laxer policy, is refused before any prompt, and a
CA slot's dialog is shown whatever the agent otherwise believes of the key's
PIN policy.

The attestation must also be signed by the card's own attestation
certificate (slot F9), exactly as for an operator act, and the whole check is
made twice: before the prompt, and again after the card is reconnected, inside
the signing session and before the PIN is verified, against the key the
request named, so a card swapped while the dialog was open cannot pass.

No CA slot's key ever performs key agreement (ECDH), on any path: it is
refused before any PIN prompt or card access, in the one place every card
operation goes through.

What the kinds refuse:

- Slot 82 (X.509) signs no DER TBSCertificate through the agent or *piggy tool
  sign* (a certificate is signed only through *piggy ca*, which says what it
  is certifying), and no OpenSSH certificate.
- Slot 83 (SSH certificate) signs only an unsigned OpenSSH *user*
  certificate, as *ssh-keygen -U -s* sends it to an agent: no TBSCertificate,
  no sshsig in any namespace, no SSH login challenge, no other bytes. A host
  certificate, a certificate that names no principal (it would be valid for
  every user), one with no end, one already over, one that starts more than
  five minutes from now, and one valid for more than 24 hours (plus five
  minutes for *ssh-keygen*'s back-dating) are refused before any prompt, and
  so is one that names a CA key other than the key asked to sign it.
  Everything the dialog shows is bounded and plain by refusal, not by
  escaping: a key id of at most 64 bytes and at most 8 principals of at most
  64, of ASCII letters and digits and the characters . \_ @ : + - only, none
  starting with a dash and none being "." or "..";
  critical options only *force-command* and
  *source-address* (a value of at most 80 printable-ASCII bytes with no
  quote, no backslash, single spaces between words only and none at either
  end, shown on a line of its own in quotes) and
  *verify-required*, and extensions only the five "permit" ones
  (X11-forwarding, agent-forwarding, port-forwarding, pty, user-rc), each at
  most once (*no-touch-required* and every unknown option are refused); a
  certified key that is not a well-formed ed25519, ECDSA (P-256, P-384,
  P-521), RSA (2048 to 8192 bits) or security-key key, a nonce that is not
  32 bytes, a key type that is not exactly one of OpenSSH's certificate
  names, and any certificate whose dialog the parser computes would take more
  than 24 lines at the dialog's 100-column wrap. *piggy tool sign*, *piggy sign-bytes* and *piggy tool req-cert*
  sign nothing with slot 83.
- Every other slot refuses an OpenSSH certificate.

The PIN of slots 82 and 83 is asked every time and never cached by the
agent; the PIN of every other slot, 9C and 9D included, is cached as before.
A certificate is signed behind a PIN dialog of kind *ssh-certificate* (see
*piggy-agent*(1), SSH CERTIFICATE AUTHORITY) that shows the certificate's key
id, principals, certified key, CA key, validity, critical options and
extensions.

# PORTABILITY CONSIDERATIONS

The "all 20 are fully available for use" guarantee is *Yubico's*. A
strictly PIV-conformant card or middleware implementation from a
different vendor may treat slots 82h-95h as retired-only and refuse
to use them as active Key Management keys. If piggy ever targets
non-YubiKey PIV hardware, the convention may not hold and code must
be prepared to fall back to 9D.

# RISKS AND GOTCHAS

*MaxAuthTries collision*
	pivy's README warns that exposing many retired-slot keys via SSH
	can collide with sshd's *MaxAuthTries 6* default. Not relevant to
	piggy's ebox decrypt path, but relevant if piggy ever surfaces
	those keys through *piggy-agent*(1).

*PIN and touch policy*
	Per-slot PIN-cache and touch policies are configurable on YubiKey
	hardware, but a generic PKCS#11 backend may not honor differing
	policies between 9D and a retired slot. Behavior is hardware-
	and middleware-dependent.

*Attestation*
	YubiKey slot F9 attests on-device-generated keys in any slot,
	including 82h-95h. No documented attestation difference between
	9D and the retired slots was found in the sources surveyed.

# REFERENCES

- NIST SP 800-73-4 landing page:
  _https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final_
- Yubico, "Certificate slots":
  _https://developers.yubico.com/PIV/Introduction/Certificate_slots.html_
- str4d, *age-plugin-yubikey*:
  _https://github.com/str4d/age-plugin-yubikey_
- arekinath, *pivy*:
  _https://github.com/arekinath/pivy_

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-ci*(7)
