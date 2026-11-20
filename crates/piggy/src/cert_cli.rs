//! `piggy cert show FILE`: a certificate's fields read back as text (FDR
//! 0007), the read-only face of `piggy_piv::x509_verify::describe`: subject,
//! issuer, serial, validity, the key as an OpenSSH line, the constraints
//! and names, the key identifiers, and the SHA-256 of the DER (the digest
//! a certificate act's description carries). A PEM holding several
//! certificates prints each. Nothing is checked; `piggy ca verify` is the
//! checker.
//!
//! Exit 0 printed; 2 usage; 4 the file is unreadable or not a certificate.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use piggy_piv::x509_verify::{self, Description};

use piggy::ecdsa_sig::openssh_ecdsa_line;

#[derive(Parser, Debug)]
#[command(
    name = "piggy cert",
    about = "Read X.509 certificates back as text (FDR 0007)",
    disable_help_subcommand = true
)]
struct CertCli {
    #[command(subcommand)]
    cmd: CertCommand,
}

#[derive(Subcommand, Debug)]
enum CertCommand {
    /// Print a certificate's fields: subject, issuer, serial, validity,
    /// key, constraints, names, key identifiers, DER sha256.
    Show {
        /// The certificate, PEM (one or more) or DER.
        file: PathBuf,
    },
}

/// The lines `show` prints for one certificate.
pub(crate) fn render(d: &Description) -> String {
    let mut lines = Vec::new();
    let mut put = |name: &str, value: String| {
        if !value.is_empty() {
            lines.push(format!("{name:<20}{value}"));
        }
    };
    put("subject:", d.subject.clone());
    put(
        "issuer:",
        if d.self_issued {
            format!("{} (self-issued)", d.issuer)
        } else {
            d.issuer.clone()
        },
    );
    put("serial:", d.serial_hex.clone());
    put("not-before:", d.not_before.clone());
    put("not-after:", d.not_after.clone());
    let curve = match &d.key {
        Some((piggy_piv::PivAlgorithm::EcP256, _)) => Some("EC P-256"),
        Some((piggy_piv::PivAlgorithm::EcP384, _)) => Some("EC P-384"),
        _ => None,
    };
    put(
        "key:",
        match (curve, &d.key) {
            (Some(curve), Some((_, point))) => format!(
                "{curve} {}",
                openssh_ecdsa_line(point, "").unwrap_or_default()
            ),
            _ => "not an EC P-256 or P-384 key".to_string(),
        },
    );
    if let Some((critical, ca, pathlen)) = d.basic_constraints {
        put(
            "basic-constraints:",
            format!(
                "{}CA:{}{}",
                if critical { "critical " } else { "" },
                if ca { "TRUE" } else { "FALSE" },
                pathlen.map(|n| format!(" pathlen:{n}")).unwrap_or_default()
            ),
        );
    }
    put("key-usage:", d.key_usage.join(", "));
    put("extended-key-usage:", d.extended_key_usage.join(", "));
    put("dns-names:", d.dns_names.join(", "));
    put("ip-names:", d.ip_names.join(", "));
    put("permitted:", d.permitted.join(", "));
    put("excluded:", d.excluded.join(", "));
    put("subject-key-id:", d.ski_hex.clone().unwrap_or_default());
    put("authority-key-id:", d.aki_hex.clone().unwrap_or_default());
    put("unknown-critical:", d.unknown_critical.join(", "));
    put("der-sha256:", d.sha256_hex.clone());
    lines.join("\n") + "\n"
}

pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy cert".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match CertCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    match args.cmd {
        CertCommand::Show { file } => match show(&file) {
            Ok(()) => 0,
            Err(failure) => {
                eprintln!("piggy cert: {}", failure.message);
                failure.exit as i32
            }
        },
    }
}

fn show(file: &std::path::Path) -> Result<(), crate::ca::Failure> {
    let ders = crate::ca::certificates_in(file)?;
    let total = ders.len();
    let mut out = std::io::stdout().lock();
    for (i, der) in ders.iter().enumerate() {
        let d = x509_verify::describe(der).map_err(|e| {
            crate::ca::failure(crate::ca::Exit::Csr)(format!("{}: {e}", file.display()))
        })?;
        let text = render(&d);
        let block = if total > 1 {
            format!("certificate {} of {total}\n{text}\n", i + 1)
        } else {
            text
        };
        out.write_all(block.as_bytes()).map_err(|e| {
            crate::ca::failure(crate::ca::Exit::Refused)(format!("write stdout: {e}"))
        })?;
    }
    out.flush()
        .map_err(|e| crate::ca::failure(crate::ca::Exit::Refused)(format!("write stdout: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_needs_a_file_and_render_skips_empty_fields() {
        assert!(CertCli::try_parse_from(["piggy cert"]).is_err());
        assert!(CertCli::try_parse_from(["piggy cert", "show"]).is_err());
        let cli = CertCli::try_parse_from(["piggy cert", "show", "root.pem"]).unwrap();
        match cli.cmd {
            CertCommand::Show { file } => assert_eq!(file.to_string_lossy(), "root.pem"),
        }
        let d = Description {
            subject: "CN=root".into(),
            issuer: "CN=root".into(),
            self_issued: true,
            serial_hex: "5a5a".into(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2027-01-01T00:00:00Z".into(),
            key: None,
            basic_constraints: Some((true, true, Some(1))),
            key_usage: vec!["keyCertSign", "cRLSign"],
            extended_key_usage: vec![],
            dns_names: vec![],
            ip_names: vec![],
            permitted: vec!["DNS:github.com".into()],
            excluded: vec!["IP:0.0.0.0/0.0.0.0".into()],
            ski_hex: Some("ab".into()),
            aki_hex: Some("ab".into()),
            unknown_critical: vec![],
            sha256_hex: "cd".into(),
        };
        let text = render(&d);
        for want in [
            "subject:            CN=root\n",
            "issuer:             CN=root (self-issued)\n",
            "basic-constraints:  critical CA:TRUE pathlen:1\n",
            "key-usage:          keyCertSign, cRLSign\n",
            "permitted:          DNS:github.com\n",
            "der-sha256:         cd\n",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        assert!(
            !text.contains("dns-names") && !text.contains("unknown-critical"),
            "{text}"
        );
    }
}
