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
