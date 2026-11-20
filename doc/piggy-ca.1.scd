piggy-ca(1)

# NAME

piggy-ca - X.509 issuance: a card-held root, a holder-held intermediate, name-constrained leaves

# SYNOPSIS

*piggy ca csr* *--key* _FILE_ [*--cn* _NAME_] [*--out* _FILE_]++
*piggy ca root-cert* *--profile* _NAME_ [*--out* _FILE_] [*--act-out* _FILE_]++
*piggy ca sign* *--profile* _NAME_ [*--out* _FILE_] [*--act-out* _FILE_]++
*piggy ca issue* *--profile* _NAME_ [*--out* _FILE_] [*--act-out* _FILE_]

# DESCRIPTION

*piggy ca* is the issuance side of FDR 0007: three certificates in a chain,
each issued by the verb that fits its place in it.

*root-cert*
	The self-signed root, over the key in the card's CA slot (82). It
	carries a name constraint, so it can certify only the names its
	profile permits.

*csr* and *sign*
	The intermediate. Its key is held by the holder agent, never by a
	person: *csr* writes the request, signed through the agent, and *sign*
	has the card-held root certify it.

*issue*
	A leaf for one of the permitted names, signed by the card-held root
	the leaf profile names, one at a time, from a request.

The verbs' flags, the certificate fields and the profile file are in
*piggy*(1) (the *ca* entries). This page is how they fit together.

## What the card signs, and how

Every certificate the card signs (*root-cert*, *sign*, *issue*) is signed
in-process on the local card, never through an agent: the agent refuses a
certificate on an ordinary sign request (RFC 0012 §2.7). Before the first
prompt the verb proves the slot's key is the card's own, by the checks
*piggy tool attest-verify* makes, and reads what the act below will need.
Then:

. one PIN prompt, whose context names the certificate (its names, validity
  and serial), and a touch;
. the *piggy-certificate-v1* act (RFC 0012 §3.2, RFC 0013), signed by the
  same card's slot 9C through the agent: a second PIN prompt and touch,
  under the *certificate* banner.

The second prompt is not a retry. The first signs the certificate; the
second puts a record of it in the ledger, naming the SHA-256 of the DER
that was signed, so a certificate with no act is one something other than
piggy signed. Because the act names the signed bytes it can only come
after the certificate, and the certificate is written only once the act is
sealed and on disk: an act that is not sealed (a cancelled prompt, the
card gone, the agent refusing) means the card's signature is dropped and
nothing is written. A P-384 key gets no act (RFC 0013 names only P-256),
so a P-384 root or request is refused before any prompt.

## Profiles

The policy is a profile, _ca-profiles/NAME.toml_ under *PIGGY_CONFIG_HOME*
(else _$XDG_CONFIG_HOME/piggy_, else _~/.config/piggy_). The consumer of
the certificates writes the names and lifetime; the operator fills
*[issuer]* (the card's GUID and slot) at install time. The request supplies
only its key: names, extensions and lifetime come from the profile, so a
request can ask for nothing the profile does not allow. A request that
does not pass is refused and nothing is signed.

## Rate limit and audit

Each profile issues at most once in ten minutes (*sign* and *issue*). A
stamp per profile, and one audit line per certificate, are kept in
*PIGGY_CA_STATE*, else _$XDG_STATE_HOME/piggy/ca_, else
_~/.local/state/piggy/ca_. The stamp is armed only after the act and the
certificate are written. The audit line names the certificate's act by
its digest, never by its contents. It guards against a runaway timer; it is not a
lock, and two runs inside one window may both pass.

# EXIT STATUS

One table for every verb, so a renewal timer reads one meaning per code.

*0*	done
*1*	refused for any other reason (on stderr), including a certificate
	written but not recorded
*2*	usage
*3*	the profile is unknown, unreadable or not of the verb's kind
*4*	the request is malformed or its key type refused
*5*	the request's names are outside the profile
*6*	the issuer key is unavailable: the card is not attached, the slot holds
	no attestable key or no certificate to issue under, the key is not
	proven the card's, the PIN was refused, or no agent serves the 9C key
*7*	rate limited

# ENVIRONMENT

*PIGGY_CONFIG_HOME*, *XDG_CONFIG_HOME*
	Where profiles are read.

*PIGGY_CA_STATE*, *XDG_STATE_HOME*
	Where the rate-limit stamp and the audit file are kept.

*PIGGY_AUTH_SOCK*, *SSH_AUTH_SOCK*
	The agent that signs the certificate act and, for *csr*, the request.

# EXAMPLES

```
piggy ca root-cert --profile shithub --out root.pem   # and root.pem.act
piggy tool write-cert 82 < root.pem
piggy ca sign --profile shithub-intermediate --out int.pem < int.csr
piggy ca issue --profile shithub-leaf --out leaf.pem < leaf.csr
openssl verify -CAfile root.pem -untrusted int.pem leaf.pem
```

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-acts*(7), *piggy-piv-slots*(7)

FDR 0007 (X.509 issuance) and RFC 0012 §3.2 and RFC 0013 (the certificate
act) in the piggy repository.
