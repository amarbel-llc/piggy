//! `piggy ca issue` with a holder issuer (FDR 0007 phase (iii-b),
//! piggy#392): the leaf signed by the holder-held intermediate key through
//! the holder agent. No card, no PIN, no touch, and no certificate act: the
//! card's act on the intermediate stands, and a holder leaf has no operator
//! to bless it (FDR 0007 step 6 leaves `act=` absent in the audit line).
//!
//! Fail closed on the agent: it must answer `agent-mode@piggy` as a holder
//! and list the key, so a plain ssh-agent never issues; either lack is the
//! issuer being unavailable (exit 6), as is a refusal to sign (the key is
//! not available to this caller: the renewal timer reads one meaning). The
//! issuer certificate is the profile's `issuer_cert`, read before the
//! request, so a profile naming what the intermediate's name constraints do
//! not admit is refused (exit 3) with nothing read from stdin. The output
//! is the leaf followed by the intermediate (FDR 0007 step 7), to `--out`
//! as one file or to stdout; the rate limit and the audit line are the
//! card path's.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use piggy::agent_client::{agent_sign_ecdsa_der, probe_agent_mode, probe_ecdsa_points};
use piggy::ca_issue::{self, Inputs, Signer, Verb};
use piggy::ca_profile::Profile;
use piggy_piv::PivError;
use ssh_key::public::{EcdsaPublicKey, KeyData};

use super::issuance::{
    IssuanceArgs, append_audit, csr_der_from, record_digest, refused, write_stamp,
};
use super::root_cert::{SERIAL_BYTES, pem_certificate};
use super::{Exit, Failure, failure};

/// How long the agent gets to answer a probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn execute(
    args: &IssuanceArgs,
    profile: &Profile,
    now: Duration,
    state: &Path,
    stamp: &Path,
) -> Result<(), Failure> {
    // The profile admitted a holder issuer on a leaf only (ca_profile), and
    // the verb's kind check ran before this: only `issue` arrives here.
    if args.act_out.is_some() {
        return Err(failure(Exit::Usage)(
            "--act-out: a leaf the holder issues leaves no certificate act (the intermediate's stands)"
                .into(),
        ));
    }
    let holder_key = profile
        .issuer
        .holder_key
        .as_deref()
        .expect("a holder issuer has holder_key");
    let issuer_path = profile
        .issuer
        .issuer_cert
        .as_deref()
        .expect("a holder issuer has issuer_cert (ca_profile)");
    let mut issuer_ders = super::certificates_in(Path::new(issuer_path))
        .map_err(|f| failure(Exit::Profile)(format!("issuer_cert: {}", f.message)))?;
    if issuer_ders.len() != 1 {
        return Err(failure(Exit::Profile)(format!(
            "issuer_cert {issuer_path}: one certificate expected, {} found",
            issuer_ders.len()
        )));
    }
    let issuer_cert = issuer_ders.remove(0);
    // The profile's names against the intermediate's constraints, before
    // the agent is asked anything and before stdin is read.
    ca_issue::check_issuer_admits(profile, &issuer_cert).map_err(refused)?;

    let key = ssh_key::PublicKey::from_openssh(holder_key.trim())
        .map_err(|e| failure(Exit::Profile)(format!("holder_key: {e}")))?;
    let point = match key.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
        other => {
            return Err(failure(Exit::Profile)(format!(
                "holder_key is {}, not ecdsa-sha2-nistp256",
                other.algorithm()
            )));
        }
    };
    let blob = key
        .to_bytes()
        .map_err(|e| failure(Exit::Profile)(format!("holder_key: {e}")))?;
    // The profile's key must be the issuer certificate's own: a stale
    // issuer_cert after the holder re-minted is the normal way to get this
    // wrong, and it is refused before the agent is asked anything.
    ca_issue::check_holder_key_is_the_issuers(&point, &issuer_cert).map_err(refused)?;
    // The PEM's directory is checked before the agent too, as the card
    // path checks the act's: an unwritable --out must not spend a signature.
    if let Some(dir) = args.out.as_deref().and_then(Path::parent) {
        if !dir.as_os_str().is_empty() && !dir.is_dir() {
            return Err(failure(Exit::Refused)(format!(
                "--out: {} is not a directory",
                dir.display()
            )));
        }
    }

    let socket = super::agent_socket().map_err(failure(Exit::IssuerUnavailable))?;
    let unavailable = failure(Exit::IssuerUnavailable);
    let mode = probe_agent_mode(&socket, PROBE_TIMEOUT).map_err(|e| {
        unavailable(format!(
            "the agent at {} did not report itself (agent-mode@piggy: {e}); a holder issues leaves, nothing else",
            socket.display()
        ))
    })?;
    if !mode.holder {
        return Err(unavailable(format!(
            "the agent at {} is not a holder; a holder key issues only through its holder",
            socket.display()
        )));
    }
    let served = probe_ecdsa_points(&socket, PROBE_TIMEOUT).map_err(|e| {
        unavailable(format!(
            "the holder at {} did not list its keys: {e}",
            socket.display()
        ))
    })?;
    if !served.contains(&point) {
        return Err(unavailable(format!(
            "the holder at {} does not serve the profile's holder_key ({})",
            socket.display(),
            key.comment()
        )));
    }

    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(1 << 20)
        .read_to_end(&mut input)
        .map_err(|e| failure(Exit::Csr)(format!("read the request from stdin: {e}")))?;
    let csr_der = csr_der_from(&input).map_err(failure(Exit::Csr))?;
    let mut random = [0u8; SERIAL_BYTES];
    openssl::rand::rand_bytes(&mut random)
        .map_err(|e| failure(Exit::Refused)(format!("random serial: {e}")))?;
    random[0] &= 0x7F;

    eprintln!(
        "piggy ca: the holder at {} signs a leaf certificate under profile {} for {} (serial {}) with the intermediate in {issuer_path}; no PIN, no touch, no act",
        socket.display(),
        args.profile,
        profile.names.join(", "),
        hex::encode(random)
    );

    let inputs = Inputs {
        verb: Verb::Issue,
        profile,
        csr_der: &csr_der,
        issuer_cert_der: &issuer_cert,
        now,
        serial: &random,
    };
    let signer = Signer::Tbs(Box::new(|tbs: &[u8]| {
        agent_sign_ecdsa_der(&socket, &blob, tbs).map_err(|e| PivError::Other(e.to_string()))
    }));
    let issued = ca_issue::issue_with(&inputs, signer).map_err(refused)?;

    // The chain the proxy serves: the leaf, then its issuer; never the root.
    let mut pem = pem_certificate(&issued.cert_der);
    pem.push_str(&pem_certificate(&issuer_cert));
    match &args.out {
        Some(path) => std::fs::write(path, &pem)
            .map_err(|e| failure(Exit::Refused)(format!("write {}: {e}", path.display())))?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(pem.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
        }
    }

    let line = ca_issue::audit_line(
        &args.profile,
        &random,
        &record_digest(&issued.cert_der),
        &record_digest(&csr_der),
        None,
        issued.requested_not_after,
    );
    write_stamp(stamp, now)
        .and_then(|()| append_audit(&state.join("audit"), &line))
        .map_err(|e| {
            failure(Exit::Refused)(format!(
                "the certificate was issued and written, but not recorded ({e}); the rate limit is not armed"
            ))
        })
}
