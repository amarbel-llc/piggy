use ssh_key::PublicKey;

use crate::apdu::PIV_TAG_CERT_YK_ATTESTATION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivAlgorithm {
    Rsa1024,
    Rsa2048,
    EcP256,
    EcP384,
    Ed25519,
}

impl PivAlgorithm {
    pub fn to_byte(&self) -> u8 {
        match self {
            PivAlgorithm::Rsa1024 => 0x06,
            PivAlgorithm::Rsa2048 => 0x07,
            PivAlgorithm::EcP256 => 0x11,
            PivAlgorithm::EcP384 => 0x14,
            PivAlgorithm::Ed25519 => 0xE0,
        }
    }
}

pub struct PivSlot {
    id: u8,
    algorithm: PivAlgorithm,
    cert_der: Vec<u8>,
    public_key: PublicKey,
}

impl PivSlot {
    pub fn new(id: u8, algorithm: PivAlgorithm, cert_der: Vec<u8>, public_key: PublicKey) -> Self {
        Self {
            id,
            algorithm,
            cert_der,
            public_key,
        }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algorithm(&self) -> PivAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn ssh_public_key_string(&self) -> String {
        self.public_key.to_openssh().unwrap_or_default()
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// pivy `piv_alg_to_string` label for this slot's key algorithm — the
    /// `algorithm` field in `pivy-tool list`.
    pub fn algorithm_label(&self) -> &'static str {
        match self.algorithm {
            PivAlgorithm::Rsa1024 => "RSA1024",
            PivAlgorithm::Rsa2048 => "RSA2048",
            PivAlgorithm::EcP256 => "ECCP256",
            PivAlgorithm::EcP384 => "ECCP384",
            PivAlgorithm::Ed25519 => "ED25519",
        }
    }

    /// OpenSSH `sshkey_type` label — the `key_type` field in `pivy-tool list`
    /// (the generic key family, not the curve).
    pub fn key_type(&self) -> &'static str {
        match self.algorithm {
            PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => "RSA",
            PivAlgorithm::EcP256 | PivAlgorithm::EcP384 => "ECDSA",
            PivAlgorithm::Ed25519 => "ED25519",
        }
    }

    /// OpenSSH `sshkey_size` — the `key_size` field in `pivy-tool list` (bits).
    pub fn key_bits(&self) -> u32 {
        match self.algorithm {
            PivAlgorithm::Rsa1024 => 1024,
            PivAlgorithm::Rsa2048 => 2048,
            PivAlgorithm::EcP256 => 256,
            PivAlgorithm::EcP384 => 384,
            PivAlgorithm::Ed25519 => 256,
        }
    }

    /// pivy `piv_slotid_to_string` name — the slot's `name` field in
    /// `pivy-tool list`.
    pub fn slot_name(&self) -> String {
        slot_id_to_string(self.id)
    }

    /// Certificate subject, issuer (both `X509_NAME_oneline`), and serial
    /// (`BN_bn2hex`) for `pivy-tool list`, parsed from this slot's cert DER.
    pub fn cert_display_fields(&self) -> Result<(String, String, String), crate::error::PivError> {
        crate::cert::display_fields(&self.cert_der)
    }
}

/// Map a PIV slot ID to pivy's `piv_slotid_to_string` name: the four standard
/// slots have mnemonic names, retired slots `82`..`95` are `retired-N`
/// (`N = id - 0x81`, so `82`→`retired-1`), and anything else is `0x%02x`.
pub fn slot_id_to_string(id: u8) -> String {
    match id {
        0x9A => "piv-auth".to_string(),
        0x9C => "piv-sign".to_string(),
        0x9D => "key-mgmt".to_string(),
        0x9E => "card-auth".to_string(),
        0x82..=0x95 => format!("retired-{}", id - 0x81),
        _ => format!("0x{id:02x}"),
    }
}

/// Map PIV slot ID to the data object tag for its certificate
pub fn slot_to_cert_tag(slot_id: u8) -> Option<u32> {
    match slot_id {
        0x9A => Some(0x5FC105),
        0x9C => Some(0x5FC10A),
        0x9D => Some(0x5FC10B),
        0x9E => Some(0x5FC101),
        0x82..=0x95 => Some(0x5FC10D + (slot_id - 0x82) as u32),
        0xF9 => Some(PIV_TAG_CERT_YK_ATTESTATION),
        _ => None,
    }
}

pub fn is_valid_piv_slot(slot_id: u8) -> bool {
    slot_to_cert_tag(slot_id).is_some()
}

/// Standard PIV slots to probe for certificates
pub const STANDARD_SLOTS: &[u8] = &[0x9A, 0x9C, 0x9D, 0x9E];
