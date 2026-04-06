# piggy requirements

A passwordstore.org fork that uses pivy-tool and eboxes instead of GPG or age.

## Core operations

- **Encrypt:** Use `pivy-box stream encrypt` to encrypt secrets to a PIV public
  key (slot 9D, Key Management). Slot 9D is the correct PIV slot for
  encryption/decryption (ECDH key agreement) per NIST SP 800-73. Slot 9A (PIV
  Authentication) is for signing/challenge-response only. Encryption only
  requires the public key --- no card touch, no agent.
- **Decrypt:** Use `pivy-tool ebox` to decrypt via pivy-agent. Card touch/PIN
  required depending on PIV policy.
- **Store layout:** passwordstore.org-compatible directory tree, one encrypted
  file per secret, git-tracked.
- **Recipients:** Equivalent of `.gpg-id` --- a file listing PIV public keys
  (ECDSA public keys from `pivy-tool pubkey`) that secrets are encrypted to.

## Local usage

- pivy-agent running locally with PIV card (YubiKey) present.
- `pivy-tool` available on PATH.
- Encrypt and decrypt both work directly.

## Remote usage (SSH)

- pivy-agent speaks the SSH agent protocol, so `SSH_AUTH_SOCK` forwarding
  (`ssh -A` or `ForwardAgent`) makes the agent available on remote hosts.
- **Decrypt works transparently:** `pivy-tool ebox` on the remote host talks to
  the forwarded agent socket, which proxies back to the local pivy-agent, which
  talks to the physical card.
- **Encrypt works without forwarding:** Only needs the public key on disk.
- **Dependency:** `pivy-tool` must be installed on any remote host where secrets
  are decrypted.

## Capability matrix

  -------------------------------------------------------------------------------
  Capability           Local                    Remote (forwarded agent)
  -------------------- ------------------------ ---------------------------------
  Encrypt (ebox        Public key only          Public key only
  create)                                       

  Decrypt (ebox        pivy-agent + card        Forwarded SSH_AUTH_SOCK + local
  unlock)                                       card

  Insert/edit secrets  Encrypt + git commit     Same

  Read secrets         Decrypt                  Decrypt via forwarded agent

  pivy-tool binary     Required                 Required

  Physical card        Required for decrypt     Required locally (not on remote)
  -------------------------------------------------------------------------------
