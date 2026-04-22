use ssh_key::PublicKey;

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
            PivAlgorithm::Ed25519 => 0x22,
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
}

/// Map PIV slot ID to the data object tag for its certificate
pub fn slot_to_cert_tag(slot_id: u8) -> Option<u32> {
    match slot_id {
        0x9A => Some(0x5FC105),
        0x9C => Some(0x5FC10A),
        0x9D => Some(0x5FC10B),
        0x9E => Some(0x5FC101),
        0x82..=0x95 => Some(0x5FC10D + (slot_id - 0x82) as u32),
        _ => None,
    }
}

/// Standard PIV slots to probe for certificates
pub const STANDARD_SLOTS: &[u8] = &[0x9A, 0x9C, 0x9D, 0x9E];
