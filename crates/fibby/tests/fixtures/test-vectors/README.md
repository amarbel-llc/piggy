# Test-vector keypairs

PEMs in this directory back fibby's byte-deterministic replay tests. They
are **public, well-known vectors** — anyone reproducing the captures must
import the same scalar into slot 9D of a throwaway card so the GA ECDH
APDU pair (which depends only on `card_priv * client_ephemeral_pub`)
matches byte-for-byte across captures. See piggy#134.

## Files

### `rfc6979-a-2-5-priv.pem`

P-256 keypair from RFC 6979 Appendix A.2.5.

- **Curve:** NIST P-256 (prime256v1, OID `1.2.840.10045.3.1.7`)
- **Private scalar (hex):**
  `C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721`
- **Public point Ux:**
  `60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6`
- **Public point Uy:**
  `7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299`

Verify with `openssl ec -in rfc6979-a-2-5-priv.pem -text -noout` — the
`pub:` block must match `04 ‖ Ux ‖ Uy`.

**Not sensitive.** RFC 6979 publishes this scalar in the public
literature for ECDSA test vectors; reusing it for ECDH replay carries no
additional disclosure risk. Do not delete or rotate; the captured
fixtures are pinned against this exact public point forever.

### `rfc5903-8-1-priv.pem`

P-256 keypair from RFC 5903 Appendix 8.1 (the initiator key of the
"256-Bit Random ECP Group" = NIST P-256). Backs fibby's slot **9D**
(Key Management / ECDH) test cert — deliberately a *different* keypair
than the §A.2.5 one used by slot 9A, so the two slots advertise distinct
public keys and pivy-agent routes a decrypt's ECDH unambiguously to 9D.

- **Curve:** NIST P-256 (prime256v1, OID `1.2.840.10045.3.1.7`)
- **Private scalar (hex):**
  `C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433`
- **Public point gix:**
  `DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180`
- **Public point giy:**
  `5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3`

Verify with `openssl pkey -in rfc5903-8-1-priv.pem -text -noout` — the
`pub:` block must match `04 ‖ gix ‖ giy`.

`virtual_card.rs::RFC5903_SLOT_9D_PRIV` pins this scalar, and
`RFC5903_SLOT_9D_CERT_OBJECT` pins a self-signed X.509 over it
(CN `fibby-test-slot-9d`, serial 1, notBefore 2026-01-01Z, notAfter
2126-01-01Z), installed at PIV tag `5F C1 0B`. The cert's ECDSA
signature uses a random `k`, so its bytes are not reproducible from this
PEM by external tools — once pinned, they are the canonical fibby
slot-9D cert. To regenerate: build an EC key from the scalar above,
`x509` self-sign with the fixed subject/serial/dates, wrap the DER in the
PIV cert-object TLV (`53 70 … 71 01 00 FE 00`), and re-pin.

**Not sensitive.** RFC 5903 publishes this scalar in the public
literature for ECDH test vectors.

### `fibby-slot-9c-test-priv.pem`

P-256 keypair backing fibby's slot **9C** (Digital Signature) test cert.

Unlike the two files above, this is **not** a published RFC vector — it is
a key fibby generated itself. The slot-9C sign path uses RFC 6979
deterministic ECDSA, so (unlike 9D's ECDH byte-replay, piggy#134) there is
no captured wire to match: all that is required is a key *distinct* from
slot 9A (§A.2.5) and slot 9D (§8.1) so pivy-agent routes signing
unambiguously to 9C. Its public point is `04 ‖ BA 37 10 C3 … ‖ … 67 20 E6
2E 89`.

`virtual_card.rs::FIBBY_SLOT_9C_TEST_PRIV` pins this scalar, and
`FIBBY_SLOT_9C_CERT_OBJECT` pins a self-signed X.509 over it (CN
`fibby-test-slot-9c`, serial 1, 100-year validity) at PIV tag `5F C1 0A`.
A unit test
(`seed_fibby_slot_9c_cert_enables_signing_and_cert_matches_key`) asserts
the pinned cert's SubjectPublicKeyInfo point matches this key, so a drift
in either constant fails CI. To regenerate the key + cert + this PEM in one
shot, run `just debug-fibby-gen-slot-9c-cert` and re-paste the printed
arrays (it produces a fresh key each run — only do so deliberately).

**Not sensitive.** A throwaway P-256 test key with no production use.
