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

There is no piggy code today that reads from or writes to the retired
slots specifically. Adding such support is a feature decision (not a
bug fix) and is out of scope for this reference page; see *piggy*(1)
for the user-facing CLI.

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
