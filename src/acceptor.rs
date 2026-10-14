//! Pure Rust Kerberos Acceptor
//!
//! Minimal Kerberos implementation for NFS RPCSEC_GSS authentication.
//! This implements just enough Kerberos to:
//! 1. Load service keys from a keytab
//! 2. Decrypt and validate AP-REQ tokens
//! 3. Extract client principal and session key
//! 4. Generate AP-REP responses
//!
//! # References
//! - RFC 4120: The Kerberos Network Authentication Service (V5)
//! - RFC 1964 / RFC 4121: The Kerberos Version 5 GSS-API Mechanism

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Kerberos error types
#[derive(Debug, thiserror::Error)]
pub enum KerberosError {
    #[error("Failed to load keytab: {0}")]
    KeytabLoad(String),

    #[error("Service principal not found in keytab: {0}")]
    PrincipalNotFound(String),

    #[error("Failed to decrypt ticket: {0}")]
    DecryptionFailed(String),

    #[error("Failed to parse Kerberos token: {0}")]
    ParseError(String),

    #[error("Invalid authenticator: {0}")]
    InvalidAuthenticator(String),

    #[error("Ticket is not valid now: {0}")]
    TicketNotValid(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, KerberosError>;

/// Kerberos encryption type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EncType {
    AES256CtsHmacSha196 = 18,
    AES128CtsHmacSha196 = 17,
    AES256CtsHmacSha384192 = 20,
    AES128CtsHmacSha256128 = 19,
}

impl EncType {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            17 => Some(EncType::AES128CtsHmacSha196),
            18 => Some(EncType::AES256CtsHmacSha196),
            19 => Some(EncType::AES128CtsHmacSha256128),
            20 => Some(EncType::AES256CtsHmacSha384192),
            _ => None,
        }
    }

    /// REMOVED. Key sizes now come from [`crate::kdf`], which is the
    /// only thing that derives keys. One `key_size()` could never express
    /// enctype 20 anyway — RFC 8009 gives it Ke = 32 but Kc = Ki = 24, and
    /// collapsing those to one number is what made the old `derive_key_aes_sha2`
    /// hand back 32-octet Kc/Ki that truncation then accepted in silence.
    /// This enum is now an IDENTIFIER for the wire and the keytab, nothing more.
    pub fn etype(&self) -> i32 {
        *self as i32
    }
}

/// Service key from keytab
#[derive(Debug, Clone)]
pub struct ServiceKey {
    pub principal: String,
    pub realm: String,
    pub kvno: u32, // Key version number
    pub enctype: EncType,
    pub key: Vec<u8>,
}

/// Kerberos keytab
#[derive(Debug)]
pub struct Keytab {
    keys: Vec<ServiceKey>,
}

impl Keytab {
    /// Load keytab from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        info!("Loading keytab from: {}", path.display());

        let mut file = File::open(path).map_err(|e| {
            KerberosError::KeytabLoad(format!("Cannot open {}: {}", path.display(), e))
        })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        Self::parse(&data)
    }

    /// Parse keytab binary format
    /// Keytab format: https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(KerberosError::ParseError("Keytab too short".to_string()));
        }

        // Check format version (0x05 0x02 = v5.2)
        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != 0x0502 {
            return Err(KerberosError::ParseError(format!(
                "Unsupported keytab version: 0x{:04x}",
                version
            )));
        }

        let mut keys = Vec::new();
        let mut offset = 2;

        // Parse entries
        while offset + 4 <= data.len() {
            // Entry size (signed 32-bit, negative means hole)
            let size = i32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;

            if size < 0 {
                // Hole in keytab (deleted entry), skip
                let hole_size = (-size) as usize;
                offset += hole_size;
                continue;
            }

            let entry_size = size as usize;
            if offset + entry_size > data.len() {
                break;
            }

            // Parse entry
            if let Ok(key) = Self::parse_entry(&data[offset..offset + entry_size]) {
                debug!(
                    "Loaded key: principal={}@{}, kvno={}, enctype={:?}",
                    key.principal, key.realm, key.kvno, key.enctype
                );
                keys.push(key);
            }

            offset += entry_size;
        }

        info!("Loaded {} keys from keytab", keys.len());
        Ok(Self { keys })
    }

    /// Parse a single keytab entry
    fn parse_entry(data: &[u8]) -> Result<ServiceKey> {
        let mut offset = 0;

        // Read principal components count
        if offset + 2 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for component count".to_string(),
            ));
        }
        let num_components = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Read realm
        if offset + 2 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for realm".to_string(),
            ));
        }
        let realm_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + realm_len > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for realm data".to_string(),
            ));
        }
        let realm = String::from_utf8_lossy(&data[offset..offset + realm_len]).to_string();
        offset += realm_len;

        // Read principal components
        let mut components = Vec::new();
        for _ in 0..num_components {
            if offset + 2 > data.len() {
                return Err(KerberosError::ParseError(
                    "Entry too short for component".to_string(),
                ));
            }
            let comp_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + comp_len > data.len() {
                return Err(KerberosError::ParseError(
                    "Entry too short for component data".to_string(),
                ));
            }
            let comp = String::from_utf8_lossy(&data[offset..offset + comp_len]).to_string();
            components.push(comp);
            offset += comp_len;
        }

        let principal = components.join("/");

        // Read name type (skip)
        if offset + 4 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for name type".to_string(),
            ));
        }
        offset += 4;

        // Read timestamp (skip)
        if offset + 4 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for timestamp".to_string(),
            ));
        }
        offset += 4;

        // Read KVNO
        if offset + 1 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for kvno".to_string(),
            ));
        }
        let kvno = data[offset] as u32;
        offset += 1;

        // Read encryption type
        if offset + 2 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for enctype".to_string(),
            ));
        }
        let enctype_val = u16::from_be_bytes([data[offset], data[offset + 1]]) as i32;
        offset += 2;

        let enctype = EncType::from_i32(enctype_val).ok_or_else(|| {
            KerberosError::ParseError(format!("Unsupported enctype: {}", enctype_val))
        })?;

        // Read key length and data
        if offset + 2 > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for key length".to_string(),
            ));
        }
        let key_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + key_len > data.len() {
            return Err(KerberosError::ParseError(
                "Entry too short for key data".to_string(),
            ));
        }
        let key = data[offset..offset + key_len].to_vec();

        Ok(ServiceKey {
            principal,
            realm,
            kvno,
            enctype,
            key,
        })
    }

    /// Find a service key for the given principal
    pub fn find_key(&self, principal: &str) -> Option<&ServiceKey> {
        // Try exact match first
        // guard-lint: allow — plain Vec iterator, no lock guard
        if let Some(key) = self.keys.iter().find(|k| k.principal == principal) {
            return Some(key);
        }

        // Try matching principal without realm
        // guard-lint: allow — plain Vec iterator, no lock guard
        if let Some(key) = self.keys.iter().find(|k| {
            let full_principal = format!("{}@{}", k.principal, k.realm);
            full_principal == principal || k.principal == principal
        }) {
            return Some(key);
        }

        None
    }

    /// Select the key a specific ticket was encrypted with.
    ///
    /// ⚠ A REAL KEYTAB HOLDS ONE KEY PER ENCTYPE FOR THE SAME PRINCIPAL —
    /// `ktadd` writes them all by default, so four entries for one
    /// service name is the ORDINARY case, not an edge case. Matching on
    /// the principal alone and taking the first hit therefore picks an
    /// arbitrary enctype, and the ticket then fails its integrity check
    /// with an HMAC mismatch that looks exactly like a wrong password.
    ///
    /// The ticket names the enctype it used, so use it. `kvno` is
    /// honoured when the ticket supplies one and a match exists, but a
    /// mismatch is not fatal: a keytab mid-rotation legitimately carries
    /// the older kvno, and the enctype+HMAC still decides correctness.
    pub fn find_key_for(
        &self,
        principal: &str,
        enctype: EncType,
        kvno: Option<u32>,
    ) -> Option<&ServiceKey> {
        // F24: bind the iterator result with a standalone `let` — never
        // hold the iterator guard across an if-let scrutinee.
        let candidates: Vec<&ServiceKey> = self
            .keys
            .iter()
            .filter(|k| {
                (k.principal == principal || format!("{}@{}", k.principal, k.realm) == principal)
                    && k.enctype == enctype
            })
            .collect();

        if let Some(v) = kvno {
            let exact = candidates.iter().find(|k| k.kvno == v).copied();
            if exact.is_some() {
                return exact;
            }
        }
        candidates.first().copied()
    }

    /// A keytab from keys already in memory (e.g. fetched from a secret
    /// store rather than a file).
    pub fn from_keys(keys: Vec<ServiceKey>) -> Self {
        Keytab { keys }
    }

    /// Get all keys (for debugging)
    pub fn keys(&self) -> &[ServiceKey] {
        &self.keys
    }
}

/// GSS-API Kerberos context
#[derive(Debug)]
pub struct KerberosContext {
    pub client_principal: String,
    pub service_principal: String,
    pub session_key: Vec<u8>,
    pub enctype: EncType,
    pub established: bool,
    pub client_realm: String,
    /// The RFC 4121 §2 base key for PER-MESSAGE tokens: "the acceptor
    /// subkey, if the acceptor asserted one; otherwise the initiator
    /// subkey from the AP-REQ authenticator; otherwise the ticket
    /// session key."
    ///
    /// The authenticator's optional subkey was parsed and then thrown
    /// away, so a client that asked for one would have had every
    /// per-message token keyed on the session key instead — bytes a
    /// real peer rejects, with nothing on this side reporting an error.
    ///
    /// This is deliberately NOT `session_key`: the AP-REP encrypted
    /// part is always sealed with the TICKET SESSION KEY (RFC 4120
    /// §5.5.2), so both have to be carried.
    pub base_key: Vec<u8>,
    pub base_key_enctype: EncType,
    /// True when the initiator supplied a subkey and it was adopted.
    pub used_initiator_subkey: bool,
}

/// Kerberos key usage constants (RFC 4120 Section 7.5.1)
#[allow(dead_code)]
mod key_usage {
    pub const AS_REP_ENC_PART: i32 = 3;
    pub const TGS_REP_ENC_PART: i32 = 8;
    pub const AP_REQ_AUTHENTICATOR: i32 = 11;
    pub const AP_REP_ENC_PART: i32 = 12;
    /// RFC 4120 §7.5.1: "AS-REP Ticket and TGS-REP Ticket ... encrypted
    /// with the service key". This server decrypted tickets under usage
    /// 8 (the TGS-REP *encrypted part*) — a wrong key against any real
    /// KDC, and the constant did not exist to reach for.
    pub const TICKET: i32 = 2;
    pub const KRB_PRIV_ENC_PART: i32 = 13;
    pub const KRB_CRED_ENC_PART: i32 = 14;
}

/// Default clock-skew tolerance for an AP-REQ authenticator, in seconds.
///
/// RFC 4120 §5.3 recommends 5 minutes. A site with worse clocks should
/// pass its own policy to [`KerberosContext::accept_token_with_skew`].
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 300;

/// APOptions bit 2 (RFC 4120 §5.5.1), in the BIT STRING's 32-bit view.
const AP_OPTS_MUTUAL_REQUIRED: u32 = 0x2000_0000;

/// RFC 4121 §4.1 mechanism token IDs, which sit between the GSS mech
/// OID and the Kerberos message.
const TOK_ID_AP_REQ: &[u8; 2] = &[0x01, 0x00];
const TOK_ID_AP_REP: &[u8; 2] = &[0x02, 0x00];

/// RFC 4121 §2 base-key selection, split out so it can be tested without
/// a KDC: "the acceptor subkey, if the acceptor asserted one; otherwise
/// the initiator subkey ...; otherwise the ticket session key."
///
/// This server asserts no acceptor subkey, so the first arm cannot fire
/// here — but the ordering is written out rather than assumed, because
/// the arm that WAS missing is the second one.
fn select_base_key(
    session_key: &SessionKey,
    initiator_subkey: Option<&SessionKey>,
) -> (Vec<u8>, EncType, bool) {
    match initiator_subkey {
        Some(sk) => (sk.key.clone(), sk.enctype, true),
        None => (session_key.key.clone(), session_key.enctype, false),
    }
}

/// Bridge to the RFC-conformant crypto in the crate root.
///
/// The primitives further down this file are NOT RFC 3961: they derive
/// Ke with Kc's constant, zero-pad where n-fold is required, and encrypt
/// with no confounder and the HMAC inside the ciphertext. Every ticket,
/// authenticator and AP-REP now goes through `crate::profile`, which is
/// pinned to published test vectors. Passing the *declared* enctype with
/// the service key also makes a key/enctype mismatch an error rather
/// than a silently short key — `kdf::derive_key` length-checks its base.
fn spec_keys(
    enctype: EncType,
    base_key: &[u8],
    usage: i32,
) -> Result<(crate::profile::Enctype, Vec<u8>, Vec<u8>)> {
    let e = enctype as i32;
    let map = |m: String| KerberosError::DecryptionFailed(m);
    let kd = crate::kdf::Enctype::from_i32(e).map_err(|x| map(x.to_string()))?;
    let pr = crate::profile::Enctype::from_i32(e).map_err(|x| map(x.to_string()))?;
    let usage = usage as u32;
    let ke = crate::kdf::derive_key(kd, base_key, usage, crate::kdf::KeyUse::Encryption)
        .map_err(|x| map(x.to_string()))?;
    let ki = crate::kdf::derive_key(kd, base_key, usage, crate::kdf::KeyUse::Integrity)
        .map_err(|x| map(x.to_string()))?;
    Ok((pr, ke, ki))
}

/// RFC 3961 §5.3 / RFC 8009 §5 decrypt. Verifies the HMAC in constant
/// time before returning any plaintext.
fn spec_decrypt(
    enctype: EncType,
    base_key: &[u8],
    usage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (pr, ke, ki) = spec_keys(enctype, base_key, usage)?;
    crate::profile::decrypt(pr, &ke, &ki, ciphertext)
        .map_err(|x| KerberosError::DecryptionFailed(x.to_string()))
}

/// RFC 3961 §5.3 / RFC 8009 §5 encrypt. Draws its own random confounder.
fn spec_encrypt(
    enctype: EncType,
    base_key: &[u8],
    usage: i32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (pr, ke, ki) = spec_keys(enctype, base_key, usage)?;
    crate::profile::encrypt(pr, &ke, &ki, plaintext)
        .map_err(|x| KerberosError::DecryptionFailed(x.to_string()))
}

//==============================================================================
// CRYPTO: see the crate's `nfold`/`kdf`/`profile`/`token` modules
//==============================================================================
//
// The AES-CTS, key-derivation and HMAC primitives that used to live here
// were removed, not ported. They were not RFC 3961/3962:
//
//   * Ke was derived with 0x99, the constant RFC 3961 §5.3 assigns to Kc,
//     and there was no way to ask for Kc at all;
//   * DR zero-padded its constant where §5.1 requires n-fold;
//   * encryption used no confounder and sealed the HMAC INSIDE the
//     ciphertext instead of appending it;
//   * the SHA-2 enctypes used a bare HMAC rather than RFC 8009's KDF, and
//     `compute_hmac`'s `use_sha1: bool` could not express SHA-384 at all,
//     so enctype 20 silently got SHA-256.
//
// Sixteen tests covered them and all sixteen were self-round-trips —
// encrypt with these functions, decrypt with these functions — which pass
// whether or not the algorithm matches the specification. That is why
// four defects survived here for the life of the file. Those tests were
// deleted rather than ported: porting a round-trip onto correct code
// rebuilds the same evidence vacuum.
//
// Replacements live in the crate's `nfold`/`kdf`/`profile`/`token` modules, pinned to published test vectors:
//   nfold   RFC 3961 §5.1 n-fold
//   kdf     RFC 3961 §5.1 DR/DK, RFC 8009 §3 KDF-HMAC-SHA2
//   profile RFC 3961 §5.3 / RFC 8009 §5 encrypt, decrypt, checksum
//   token   RFC 4121 §4.2 per-message Wrap and MIC
// Reach them through `spec_encrypt` / `spec_decrypt` above.

/// Get current time in seconds since epoch
fn current_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

//==============================================================================
// PHASE 3: TICKET STRUCTURES AND DECRYPTION
//==============================================================================

/// Encrypted data structure (EncryptedData from RFC 4120)
#[derive(Debug, Clone)]
struct EncryptedData {
    enctype: EncType,
    kvno: Option<u32>,
    cipher: Vec<u8>,
}

impl EncryptedData {
    /// Parse EncryptedData from ASN.1 DER
    fn parse(data: &[u8]) -> Result<Self> {
        // EncryptedData ::= SEQUENCE {
        //   etype[0] INTEGER,
        //   kvno[1] INTEGER OPTIONAL,
        //   cipher[2] OCTET STRING
        // }

        let (tag, _len, header_size) = parse_der_tag_length(data)?;
        if tag != 0x30 {
            // SEQUENCE
            return Err(KerberosError::ParseError(format!(
                "Expected SEQUENCE for EncryptedData, got 0x{:02x}",
                tag
            )));
        }

        let content = &data[header_size..];

        // Parse etype[0]
        let (etype_data, mut remaining) = extract_tagged_field(content, 0xA0)?;
        let enctype_val = parse_asn1_integer(etype_data)?;
        let enctype = EncType::from_i32(enctype_val).ok_or_else(|| {
            KerberosError::ParseError(format!("Unknown enctype: {}", enctype_val))
        })?;

        // Try to parse kvno[1] (optional)
        let kvno = if !remaining.is_empty() && remaining[0] == 0xA1 {
            let (kvno_data, rest) = extract_tagged_field(remaining, 0xA1)?;
            remaining = rest;
            Some(parse_asn1_integer(kvno_data)? as u32)
        } else {
            None
        };

        // Parse cipher[2]
        let (cipher_data, _) = extract_tagged_field(remaining, 0xA2)?;
        let cipher = parse_asn1_octet_string(cipher_data)?;

        Ok(EncryptedData {
            enctype,
            kvno,
            cipher,
        })
    }

    /// Encode EncryptedData to ASN.1 DER
    fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();

        // etype[0]
        content.push(0xA0);
        let etype_bytes = encode_asn1_integer(self.enctype as i32);
        KerberosContext::encode_length(&mut content, etype_bytes.len());
        content.extend_from_slice(&etype_bytes);

        // kvno[1] (optional)
        if let Some(kvno) = self.kvno {
            content.push(0xA1);
            let kvno_bytes = encode_asn1_integer(kvno as i32);
            KerberosContext::encode_length(&mut content, kvno_bytes.len());
            content.extend_from_slice(&kvno_bytes);
        }

        // cipher[2]
        content.push(0xA2);
        let cipher_bytes = encode_asn1_octet_string(&self.cipher);
        KerberosContext::encode_length(&mut content, cipher_bytes.len());
        content.extend_from_slice(&cipher_bytes);

        // Wrap in SEQUENCE
        let mut result = vec![0x30];
        KerberosContext::encode_length(&mut result, content.len());
        result.extend_from_slice(&content);

        result
    }
}

/// Session key extracted from ticket
#[derive(Debug, Clone)]
struct SessionKey {
    enctype: EncType,
    key: Vec<u8>,
}

/// Kerberos ticket (RFC 4120 Section 5.3)
#[derive(Debug)]
struct Ticket {
    realm: String,
    sname: Vec<String>,
    enc_part: EncryptedData,
}

impl Ticket {
    /// Parse ticket from AP-REQ
    fn parse(data: &[u8]) -> Result<Self> {
        // Ticket ::= [APPLICATION 1] SEQUENCE {
        //   tkt-vno[0] INTEGER (5),
        //   realm[1] Realm,
        //   sname[2] PrincipalName,
        //   enc-part[3] EncryptedData
        // }

        let (tag, _len, header_size) = parse_der_tag_length(data)?;
        if tag != 0x61 {
            // APPLICATION 1
            return Err(KerberosError::ParseError(format!(
                "Expected APPLICATION 1 for Ticket, got 0x{:02x}",
                tag
            )));
        }

        // Parse inner SEQUENCE
        let seq_data = &data[header_size..];
        let (seq_tag, _seq_len, seq_header) = parse_der_tag_length(seq_data)?;
        if seq_tag != 0x30 {
            return Err(KerberosError::ParseError(
                "Expected SEQUENCE in Ticket".to_string(),
            ));
        }

        let content = &seq_data[seq_header..];

        // Parse tkt-vno[0] (should be 5)
        let (vno_data, mut remaining) = extract_tagged_field(content, 0xA0)?;
        let vno = parse_asn1_integer(vno_data)?;
        if vno != 5 {
            return Err(KerberosError::ParseError(format!(
                "Expected tkt-vno=5, got {}",
                vno
            )));
        }

        // Parse realm[1]
        let (realm_data, rest) = extract_tagged_field(remaining, 0xA1)?;
        let realm = parse_asn1_general_string(realm_data)?;
        remaining = rest;

        // Parse sname[2] (PrincipalName)
        let (sname_data, rest) = extract_tagged_field(remaining, 0xA2)?;
        let sname = parse_principal_name(sname_data)?;
        remaining = rest;

        // Parse enc-part[3]
        let (enc_data, _) = extract_tagged_field(remaining, 0xA3)?;
        let enc_part = EncryptedData::parse(enc_data)?;

        Ok(Ticket {
            realm,
            sname,
            enc_part,
        })
    }

    /// Decrypt ticket and extract session key
    fn decrypt(&self, service_key: &ServiceKey) -> Result<EncTicketPart> {
        debug!(
            "   Decrypting ticket with service key (enctype={:?})",
            service_key.enctype
        );

        // Usage 2 — RFC 4120 §7.5.1. This was TGS_REP_ENC_PART (8), the
        // usage for the TGS-REP *encrypted part*, which derives a
        // different key and cannot decrypt any real KDC's ticket.
        let data = spec_decrypt(
            self.enc_part.enctype,
            &service_key.key,
            key_usage::TICKET,
            &self.enc_part.cipher,
        )?;

        debug!("   ✅ Ticket checksum verified");

        // Parse decrypted content
        EncTicketPart::parse(&data)
    }
}

/// Decrypted ticket content (EncTicketPart from RFC 4120)
#[derive(Debug)]
struct EncTicketPart {
    flags: u32,
    key: SessionKey,
    crealm: String,
    cname: Vec<String>,
    /// Parsed because the ASN.1 walk has to step over it to reach
    /// `starttime`/`endtime`; nothing validates against it.
    #[allow(dead_code)]
    authtime: i64,
    starttime: Option<i64>,
    endtime: i64,
}

/// RFC 4120 §5.3 TicketFlags: bit 0 is the MOST significant bit of the
/// BIT STRING, so RFC flag `n` sits at u32 bit `31 - n`. `invalid` is
/// flag 7.
const TICKET_FLAG_INVALID: u32 = 1 << (31 - 7);

impl EncTicketPart {
    /// RFC 4120 §3.2.3: the acceptor checks the ticket is CURRENT, not
    /// merely decryptable.
    ///
    /// Nothing read `starttime` or `endtime` before this; the only clock
    /// check on the accept path was the authenticator's `ctime` skew, and
    /// the authenticator is minted fresh by whoever holds the session
    /// key. So a ticket stayed usable forever after its endtime: revoking
    /// a principal at the KDC did not stop anyone already holding a
    /// ticket and its session key. `#[allow(dead_code)]` on this struct
    /// was the compiler saying so.
    ///
    /// `tolerance_seconds` is the same clock-skew allowance the
    /// authenticator gets, so a recorded fixture replayed under a wide
    /// tolerance still validates and production still gets 5 minutes.
    fn validate_validity(&self, now: i64, tolerance_seconds: i64) -> Result<()> {
        // RFC 4120 §3.2.3: a postdated ticket that has not been validated
        // carries INVALID and must be refused outright, whatever the clock
        // says.
        if self.flags & TICKET_FLAG_INVALID != 0 {
            return Err(KerberosError::TicketNotValid(
                "ticket carries the INVALID flag (postdated, not yet validated)".to_string(),
            ));
        }
        if now > self.endtime.saturating_add(tolerance_seconds) {
            return Err(KerberosError::TicketNotValid(format!(
                "ticket expired at {} (now {}, tolerance {}s)",
                self.endtime, now, tolerance_seconds
            )));
        }
        if let Some(start) = self.starttime {
            if now.saturating_add(tolerance_seconds) < start {
                return Err(KerberosError::TicketNotValid(format!(
                    "ticket not valid until {} (now {}, tolerance {}s)",
                    start, now, tolerance_seconds
                )));
            }
        }
        Ok(())
    }

    /// Parse decrypted ticket content
    fn parse(data: &[u8]) -> Result<Self> {
        // EncTicketPart ::= [APPLICATION 3] SEQUENCE {
        //   flags[0] TicketFlags,
        //   key[1] EncryptionKey,
        //   crealm[2] Realm,
        //   cname[3] PrincipalName,
        //   transited[4] TransitedEncoding,
        //   authtime[5] KerberosTime,
        //   starttime[6] KerberosTime OPTIONAL,
        //   endtime[7] KerberosTime,
        //   ...
        // }

        let (tag, _len, header_size) = parse_der_tag_length(data)?;
        if tag != 0x63 {
            // APPLICATION 3
            return Err(KerberosError::ParseError(format!(
                "Expected APPLICATION 3 for EncTicketPart, got 0x{:02x}",
                tag
            )));
        }

        let seq_data = &data[header_size..];
        let (seq_tag, _seq_len, seq_header) = parse_der_tag_length(seq_data)?;
        if seq_tag != 0x30 {
            return Err(KerberosError::ParseError("Expected SEQUENCE".to_string()));
        }

        let content = &seq_data[seq_header..];

        // Parse flags[0]
        let (flags_data, mut remaining) = extract_tagged_field(content, 0xA0)?;
        let flags = parse_asn1_bit_string(flags_data)?;

        // Parse key[1] - THE SESSION KEY!
        let (key_data, rest) = extract_tagged_field(remaining, 0xA1)?;
        let key = parse_encryption_key(key_data)?;
        remaining = rest;

        debug!(
            "   🔑 Extracted session key: {} bytes, enctype={:?}",
            key.key.len(),
            key.enctype
        );

        // Parse crealm[2]
        let (crealm_data, rest) = extract_tagged_field(remaining, 0xA2)?;
        let crealm = parse_asn1_general_string(crealm_data)?;
        remaining = rest;

        // Parse cname[3]
        let (cname_data, rest) = extract_tagged_field(remaining, 0xA3)?;
        let cname = parse_principal_name(cname_data)?;
        remaining = rest;

        // Skip transited[4]
        let (_, rest) = extract_tagged_field(remaining, 0xA4)?;
        remaining = rest;

        // Parse authtime[5]
        let (authtime_data, rest) = extract_tagged_field(remaining, 0xA5)?;
        let authtime = parse_kerberos_time(authtime_data)?;
        remaining = rest;

        // Parse optional starttime[6]
        let starttime = if !remaining.is_empty() && remaining[0] == 0xA6 {
            let (time_data, rest) = extract_tagged_field(remaining, 0xA6)?;
            remaining = rest;
            Some(parse_kerberos_time(time_data)?)
        } else {
            None
        };

        // Parse endtime[7]
        let (endtime_data, _) = extract_tagged_field(remaining, 0xA7)?;
        let endtime = parse_kerberos_time(endtime_data)?;

        Ok(EncTicketPart {
            flags,
            key,
            crealm,
            cname,
            authtime,
            starttime,
            endtime,
        })
    }
}

//==============================================================================
// PHASE 4: AUTHENTICATOR VALIDATION
//==============================================================================

/// Kerberos Authenticator (RFC 4120 Section 5.5.1)
#[derive(Debug)]
#[allow(dead_code)]
struct Authenticator {
    crealm: String,
    cname: Vec<String>,
    cusec: u32,
    ctime: i64,
    subkey: Option<SessionKey>,
    seq_number: Option<u32>,
}

impl Authenticator {
    /// Parse and decrypt authenticator from AP-REQ
    fn parse_and_decrypt(enc_data: &[u8], session_key: &SessionKey) -> Result<Self> {
        // Usage 11 was already right; the crypto under it was not.
        let data = spec_decrypt(
            session_key.enctype,
            &session_key.key,
            key_usage::AP_REQ_AUTHENTICATOR,
            enc_data,
        )
        .map_err(|e| KerberosError::InvalidAuthenticator(e.to_string()))?;

        debug!("   ✅ Authenticator checksum verified");

        // Parse authenticator structure
        Self::parse_from_plaintext(&data)
    }

    /// Parse Authenticator structure from plaintext
    fn parse_from_plaintext(data: &[u8]) -> Result<Self> {
        // Authenticator ::= [APPLICATION 2] SEQUENCE {
        //   authenticator-vno[0] INTEGER (5),
        //   crealm[1] Realm,
        //   cname[2] PrincipalName,
        //   cksum[3] Checksum OPTIONAL,
        //   cusec[4] Microseconds,
        //   ctime[5] KerberosTime,
        //   subkey[6] EncryptionKey OPTIONAL,
        //   seq-number[7] INTEGER OPTIONAL
        // }

        let (tag, _len, header_size) = parse_der_tag_length(data)?;
        // RFC 4120 §5.10 assigns the Authenticator APPLICATION **2**
        // (0x62). This checked for APPLICATION 11 (0x6b) — which is
        // AS-REP's tag, and also the key usage number for the AP-REQ
        // authenticator, which is where the 11 almost certainly came
        // from. The two are unrelated numbers that happen to collide.
        if tag != 0x62 {
            // APPLICATION 2
            return Err(KerberosError::ParseError(format!(
                "Expected APPLICATION 2 for Authenticator, got 0x{:02x}",
                tag
            )));
        }

        let seq_data = &data[header_size..];
        let (seq_tag, _seq_len, seq_header) = parse_der_tag_length(seq_data)?;
        if seq_tag != 0x30 {
            return Err(KerberosError::ParseError("Expected SEQUENCE".to_string()));
        }

        let content = &seq_data[seq_header..];

        // Parse authenticator-vno[0]
        let (vno_data, mut remaining) = extract_tagged_field(content, 0xA0)?;
        let vno = parse_asn1_integer(vno_data)?;
        if vno != 5 {
            return Err(KerberosError::ParseError(format!(
                "Expected authenticator-vno=5, got {}",
                vno
            )));
        }

        // Parse crealm[1]
        let (crealm_data, rest) = extract_tagged_field(remaining, 0xA1)?;
        let crealm = parse_asn1_general_string(crealm_data)?;
        remaining = rest;

        // Parse cname[2]
        let (cname_data, rest) = extract_tagged_field(remaining, 0xA2)?;
        let cname = parse_principal_name(cname_data)?;
        remaining = rest;

        // Skip optional cksum[3]
        if !remaining.is_empty() && remaining[0] == 0xA3 {
            let (_, rest) = extract_tagged_field(remaining, 0xA3)?;
            remaining = rest;
        }

        // Parse cusec[4]
        let (cusec_data, rest) = extract_tagged_field(remaining, 0xA4)?;
        let cusec = parse_asn1_integer(cusec_data)? as u32;
        remaining = rest;

        // Parse ctime[5]
        let (ctime_data, rest) = extract_tagged_field(remaining, 0xA5)?;
        let ctime = parse_kerberos_time(ctime_data)?;
        remaining = rest;

        // Parse optional subkey[6]
        let subkey = if !remaining.is_empty() && remaining[0] == 0xA6 {
            let (subkey_data, rest) = extract_tagged_field(remaining, 0xA6)?;
            remaining = rest;
            Some(parse_encryption_key(subkey_data)?)
        } else {
            None
        };

        // Parse optional seq-number[7]
        let seq_number = if !remaining.is_empty() && remaining[0] == 0xA7 {
            let (seq_data, _) = extract_tagged_field(remaining, 0xA7)?;
            Some(parse_asn1_integer(seq_data)? as u32)
        } else {
            None
        };

        Ok(Authenticator {
            crealm,
            cname,
            cusec,
            ctime,
            subkey,
            seq_number,
        })
    }

    /// Validate authenticator timestamp
    fn validate(&self, now: i64, tolerance_seconds: i64) -> Result<()> {
        let time_diff = (now - self.ctime).abs();

        if time_diff > tolerance_seconds {
            return Err(KerberosError::InvalidAuthenticator(format!(
                "Time skew too large: {} seconds (tolerance: {})",
                time_diff, tolerance_seconds
            )));
        }

        debug!(
            "   ✅ Authenticator timestamp validated (skew: {}s)",
            time_diff
        );
        Ok(())
    }
}

//==============================================================================
// PHASE 5: AP-REP ENCRYPTION
//==============================================================================

/// Encrypted AP-REP part (EncAPRepPart from RFC 4120)
#[derive(Debug)]
struct EncAPRepPart {
    ctime: i64,
    cusec: u32,
    subkey: Option<SessionKey>,
    seq_number: Option<u32>,
}

impl EncAPRepPart {
    /// Create encrypted AP-REP part
    fn create(ctime: i64, cusec: u32, subkey: Option<SessionKey>) -> Self {
        Self {
            ctime,
            cusec,
            subkey,
            seq_number: Some(0),
        }
    }

    /// Encode as ASN.1 DER
    fn encode_asn1(&self) -> Vec<u8> {
        // EncAPRepPart ::= [APPLICATION 27] SEQUENCE {
        //   ctime[0] KerberosTime,
        //   cusec[1] Microseconds,
        //   subkey[2] EncryptionKey OPTIONAL,
        //   seq-number[3] INTEGER OPTIONAL
        // }

        let mut content = Vec::new();

        // ctime[0]
        content.push(0xA0);
        let ctime_bytes = encode_kerberos_time(self.ctime);
        KerberosContext::encode_length(&mut content, ctime_bytes.len());
        content.extend_from_slice(&ctime_bytes);

        // cusec[1]
        content.push(0xA1);
        let cusec_bytes = encode_asn1_integer(self.cusec as i32);
        KerberosContext::encode_length(&mut content, cusec_bytes.len());
        content.extend_from_slice(&cusec_bytes);

        // subkey[2] (optional)
        if let Some(ref subkey) = self.subkey {
            content.push(0xA2);
            let subkey_bytes = encode_encryption_key(subkey);
            KerberosContext::encode_length(&mut content, subkey_bytes.len());
            content.extend_from_slice(&subkey_bytes);
        }

        // seq-number[3] (optional)
        if let Some(seq_num) = self.seq_number {
            content.push(0xA3);
            let seq_bytes = encode_asn1_integer(seq_num as i32);
            KerberosContext::encode_length(&mut content, seq_bytes.len());
            content.extend_from_slice(&seq_bytes);
        }

        // Wrap in SEQUENCE
        let mut seq = vec![0x30];
        KerberosContext::encode_length(&mut seq, content.len());
        seq.extend_from_slice(&content);

        // Wrap in APPLICATION 27
        let mut result = vec![0x7B]; // APPLICATION 27
        KerberosContext::encode_length(&mut result, seq.len());
        result.extend_from_slice(&seq);

        result
    }

    /// Encrypt and return as EncryptedData
    fn encrypt(&self, session_key: &SessionKey) -> Result<Vec<u8>> {
        let plaintext = self.encode_asn1();

        // RFC 3961 §5.3: a random confounder, and the HMAC APPENDED to
        // the ciphertext rather than sealed inside it.
        let ciphertext = spec_encrypt(
            session_key.enctype,
            &session_key.key,
            key_usage::AP_REP_ENC_PART,
            &plaintext,
        )?;

        // Wrap in EncryptedData structure
        let enc_data = EncryptedData {
            enctype: session_key.enctype,
            kvno: None,
            cipher: ciphertext,
        };

        Ok(enc_data.encode())
    }
}

//==============================================================================
// PHASE 7: ASN.1 PARSING HELPERS
//==============================================================================

/// Parse ASN.1 INTEGER
fn parse_asn1_integer(data: &[u8]) -> Result<i32> {
    let (tag, length, header_size) = parse_der_tag_length(data)?;
    if tag != 0x02 {
        // INTEGER
        return Err(KerberosError::ParseError(format!(
            "Expected INTEGER tag 0x02, got 0x{:02x}",
            tag
        )));
    }

    let int_bytes = &data[header_size..header_size + length];

    // Big-endian two's complement: sign-extend from the first octet.
    let mut value: i32 = if int_bytes.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for &byte in int_bytes {
        value = (value << 8) | (byte as i32);
    }

    Ok(value)
}

/// Parse ASN.1 OCTET STRING
fn parse_asn1_octet_string(data: &[u8]) -> Result<Vec<u8>> {
    let (tag, length, header_size) = parse_der_tag_length(data)?;
    if tag != 0x04 {
        // OCTET STRING
        return Err(KerberosError::ParseError(format!(
            "Expected OCTET STRING tag 0x04, got 0x{:02x}",
            tag
        )));
    }

    Ok(data[header_size..header_size + length].to_vec())
}

/// Parse ASN.1 GeneralString (or any string type)
fn parse_asn1_general_string(data: &[u8]) -> Result<String> {
    let (tag, length, header_size) = parse_der_tag_length(data)?;

    // Accept various string types: GeneralString (0x1B), IA5String (0x16), etc.
    if ![0x1B, 0x16, 0x0C, 0x13].contains(&tag) {
        return Err(KerberosError::ParseError(format!(
            "Expected string tag, got 0x{:02x}",
            tag
        )));
    }

    let bytes = &data[header_size..header_size + length];
    Ok(String::from_utf8_lossy(bytes).to_string())
}

/// Parse ASN.1 BIT STRING (for flags)
fn parse_asn1_bit_string(data: &[u8]) -> Result<u32> {
    let (tag, length, header_size) = parse_der_tag_length(data)?;
    if tag != 0x03 {
        // BIT STRING
        return Err(KerberosError::ParseError(format!(
            "Expected BIT STRING tag 0x03, got 0x{:02x}",
            tag
        )));
    }

    let bit_data = &data[header_size..header_size + length];
    if bit_data.is_empty() {
        return Ok(0);
    }

    // First byte is number of unused bits in last byte
    let _unused_bits = bit_data[0];

    // Convert remaining bytes to u32
    let mut value = 0u32;
    for &byte in &bit_data[1..] {
        value = (value << 8) | (byte as u32);
    }

    Ok(value)
}

/// Parse Kerberos PrincipalName
fn parse_principal_name(data: &[u8]) -> Result<Vec<String>> {
    // PrincipalName ::= SEQUENCE {
    //   name-type[0] INTEGER,
    //   name-string[1] SEQUENCE OF GeneralString
    // }

    let (tag, _len, header_size) = parse_der_tag_length(data)?;
    if tag != 0x30 {
        // SEQUENCE
        return Err(KerberosError::ParseError(
            "Expected SEQUENCE for PrincipalName".to_string(),
        ));
    }

    let content = &data[header_size..];

    // Skip name-type[0]
    let (_, remaining) = extract_tagged_field(content, 0xA0)?;

    // Parse name-string[1] SEQUENCE OF
    let (name_seq_data, _) = extract_tagged_field(remaining, 0xA1)?;

    let (seq_tag, _seq_len, seq_header) = parse_der_tag_length(name_seq_data)?;
    if seq_tag != 0x30 {
        return Err(KerberosError::ParseError(
            "Expected SEQUENCE OF".to_string(),
        ));
    }

    // Parse each string in the sequence
    let mut components = Vec::new();
    let mut pos = seq_header;
    let seq_content = name_seq_data;

    while pos < seq_content.len() {
        let (tag, length, header) = parse_der_tag_length(&seq_content[pos..])?;
        if ![0x1B, 0x16, 0x0C, 0x13].contains(&tag) {
            break;
        }

        let str_bytes = &seq_content[pos + header..pos + header + length];
        components.push(String::from_utf8_lossy(str_bytes).to_string());
        pos += header + length;
    }

    Ok(components)
}

/// Parse EncryptionKey structure
fn parse_encryption_key(data: &[u8]) -> Result<SessionKey> {
    // EncryptionKey ::= SEQUENCE {
    //   keytype[0] INTEGER,
    //   keyvalue[1] OCTET STRING
    // }

    let (tag, _len, header_size) = parse_der_tag_length(data)?;
    if tag != 0x30 {
        return Err(KerberosError::ParseError(
            "Expected SEQUENCE for EncryptionKey".to_string(),
        ));
    }

    let content = &data[header_size..];

    // Parse keytype[0]
    let (keytype_data, remaining) = extract_tagged_field(content, 0xA0)?;
    let enctype_val = parse_asn1_integer(keytype_data)?;
    let enctype = EncType::from_i32(enctype_val)
        .ok_or_else(|| KerberosError::ParseError(format!("Unknown enctype: {}", enctype_val)))?;

    // Parse keyvalue[1]
    let (keyvalue_data, _) = extract_tagged_field(remaining, 0xA1)?;
    let key = parse_asn1_octet_string(keyvalue_data)?;

    Ok(SessionKey { enctype, key })
}

/// Parse KerberosTime (GeneralizedTime)
///
/// Parses ASN.1 GeneralizedTime format: "YYYYMMDDHHMMSSz"
/// where 'z' or 'Z' indicates UTC timezone.
///
/// # Format
/// - YYYY: 4-digit year
/// - MM: 2-digit month (01-12)
/// - DD: 2-digit day (01-31)
/// - HH: 2-digit hour (00-23)
/// - MM: 2-digit minute (00-59)
/// - SS: 2-digit second (00-60, 60 = leap second)
/// - z/Z: UTC indicator
///
/// # Returns
/// Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn parse_kerberos_time(data: &[u8]) -> Result<i64> {
    // KerberosTime is GeneralizedTime: YYYYMMDDHHMMSSz
    let (tag, length, header_size) = parse_der_tag_length(data)?;
    if tag != 0x18 {
        // GeneralizedTime
        return Err(KerberosError::ParseError(format!(
            "Expected GeneralizedTime tag 0x18, got 0x{:02x}",
            tag
        )));
    }

    let time_bytes = &data[header_size..header_size + length];
    let time_str = std::str::from_utf8(time_bytes).map_err(|e| {
        KerberosError::ParseError(format!("Invalid UTF-8 in GeneralizedTime: {}", e))
    })?;

    debug!("   Parsing KerberosTime: {}", time_str);

    // Expected format: "YYYYMMDDHHMMSSz" (15 characters)
    if time_str.len() < 15 {
        return Err(KerberosError::ParseError(format!(
            "GeneralizedTime too short: {} (expected 15 chars)",
            time_str.len()
        )));
    }

    // Parse components
    let year = parse_digits(&time_str[0..4], "year")?;
    let month = parse_digits(&time_str[4..6], "month")?;
    let day = parse_digits(&time_str[6..8], "day")?;
    let hour = parse_digits(&time_str[8..10], "hour")?;
    let minute = parse_digits(&time_str[10..12], "minute")?;
    let second = parse_digits(&time_str[12..14], "second")?;

    // Verify UTC indicator
    let tz_indicator = time_str.chars().nth(14).unwrap_or(' ');
    if tz_indicator != 'Z' && tz_indicator != 'z' {
        return Err(KerberosError::ParseError(format!(
            "Expected UTC indicator 'Z', got '{}'",
            tz_indicator
        )));
    }

    // Validate ranges
    if month < 1 || month > 12 {
        return Err(KerberosError::ParseError(format!(
            "Invalid month: {}",
            month
        )));
    }
    if day < 1 || day > 31 {
        return Err(KerberosError::ParseError(format!("Invalid day: {}", day)));
    }
    if hour > 23 {
        return Err(KerberosError::ParseError(format!("Invalid hour: {}", hour)));
    }
    if minute > 59 {
        return Err(KerberosError::ParseError(format!(
            "Invalid minute: {}",
            minute
        )));
    }
    if second > 60 {
        // 60 allowed for leap seconds
        return Err(KerberosError::ParseError(format!(
            "Invalid second: {}",
            second
        )));
    }

    // Convert to Unix timestamp
    // This is a simplified calculation - proper implementation would use
    // a time library, but we avoid dependencies for this critical security code
    let timestamp = calculate_unix_timestamp(year, month, day, hour, minute, second)?;

    debug!(
        "   Parsed timestamp: {} ({}-{:02}-{:02} {:02}:{:02}:{:02} UTC)",
        timestamp, year, month, day, hour, minute, second
    );

    Ok(timestamp)
}

/// Parse decimal digits from string
fn parse_digits(s: &str, field_name: &str) -> Result<i32> {
    s.parse::<i32>().map_err(|e| {
        KerberosError::ParseError(format!("Failed to parse {}: {} ('{}')", field_name, e, s))
    })
}

/// Calculate Unix timestamp from date/time components
///
/// Simplified calculation without external dependencies.
/// Accurate for dates from 1970 onwards.
fn calculate_unix_timestamp(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
) -> Result<i64> {
    if year < 1970 {
        return Err(KerberosError::ParseError(format!(
            "Year {} is before Unix epoch (1970)",
            year
        )));
    }

    // Days in each month (non-leap year)
    const DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // Calculate days since epoch
    let mut days: i64 = 0;

    // Add complete years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add complete months in current year
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize] as i64;
        // Add leap day if February and leap year
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days in current month (subtract 1 because day 1 = 0 days elapsed)
    days += (day - 1) as i64;

    // Convert to seconds and add time components
    let timestamp = days * 86400  // days to seconds
        + (hour as i64) * 3600    // hours to seconds
        + (minute as i64) * 60    // minutes to seconds
        + second as i64;

    Ok(timestamp)
}

/// Check if year is a leap year
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Encode ASN.1 INTEGER
fn encode_asn1_integer(value: i32) -> Vec<u8> {
    // DER INTEGER is minimal TWO'S COMPLEMENT. Stripping every leading
    // zero octet (as this once did) turns 200 into `02 01 C8`, which every
    // decoder reads as -56. For the AP-REP's cusec that is a broken echo
    // whenever the microseconds land in 128..=255 or 32768..=65535 —
    // about 1 handshake in 30 — and the client rejects mutual auth with
    // KRB_AP_ERR_MUT_FAIL.
    crate::der::int(value as i64)
}

/// Encode ASN.1 OCTET STRING
fn encode_asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    KerberosContext::encode_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

/// Encode KerberosTime as GeneralizedTime
#[allow(dead_code)]
fn encode_kerberos_time(timestamp: i64) -> Vec<u8> {
    // ⚠ This IGNORED its argument and encoded `Utc::now()` — "for
    // simplicity", per the comment it replaced.
    //
    // The only caller is the AP-REP's EncAPRepPart, whose ctime and
    // cusec MUST echo the AP-REQ authenticator's EXACTLY (RFC 4120
    // §3.2.5). That echo IS mutual authentication: it is the client's
    // only proof that the server could decrypt the authenticator, and a
    // client MUST reject a mismatch with KRB_AP_ERR_MUT_FAIL.
    //
    // So every AP-REP this server ever sent carried the server's clock
    // instead of the client's timestamp, and mutual authentication could
    // never have succeeded — which is precisely how a real `mount -o
    // sec=krb5p` failed: the client accepted the context handle, then
    // threw the context away when `gss_init_sec_context` rejected the
    // AP-REP, and retried until it gave up with "access denied".
    // Format: YYYYMMDDHHMMSSZ
    let dt = chrono::DateTime::from_timestamp(timestamp, 0).unwrap_or_else(chrono::Utc::now);
    let time_str = format!("{}Z", dt.format("%Y%m%d%H%M%S"));

    let mut result = vec![0x18]; // GeneralizedTime tag
    result.push(time_str.len() as u8);
    result.extend_from_slice(time_str.as_bytes());

    result
}

/// Encode EncryptionKey
fn encode_encryption_key(key: &SessionKey) -> Vec<u8> {
    let mut content = Vec::new();

    // keytype[0]
    content.push(0xA0);
    let keytype_bytes = encode_asn1_integer(key.enctype as i32);
    KerberosContext::encode_length(&mut content, keytype_bytes.len());
    content.extend_from_slice(&keytype_bytes);

    // keyvalue[1]
    content.push(0xA1);
    let keyvalue_bytes = encode_asn1_octet_string(&key.key);
    KerberosContext::encode_length(&mut content, keyvalue_bytes.len());
    content.extend_from_slice(&keyvalue_bytes);

    // Wrap in SEQUENCE
    let mut result = vec![0x30];
    KerberosContext::encode_length(&mut result, content.len());
    result.extend_from_slice(&content);

    result
}

/// Parse ASN.1 DER length
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(KerberosError::ParseError("Empty data".to_string()));
    }

    if data[0] < 0x80 {
        // Short form
        Ok((data[0] as usize, 1))
    } else {
        // Long form
        let num_octets = (data[0] & 0x7F) as usize;
        if data.len() < 1 + num_octets {
            return Err(KerberosError::ParseError("Incomplete length".to_string()));
        }

        let mut length = 0usize;
        for i in 0..num_octets {
            length = (length << 8) | (data[1 + i] as usize);
        }
        Ok((length, 1 + num_octets))
    }
}

/// Parse ASN.1 DER tag and length, return (tag, length, header_size)
fn parse_der_tag_length(data: &[u8]) -> Result<(u8, usize, usize)> {
    if data.is_empty() {
        return Err(KerberosError::ParseError("Empty data for tag".to_string()));
    }

    let tag = data[0];
    let (length, length_bytes) = parse_der_length(&data[1..])?;

    Ok((tag, length, 1 + length_bytes))
}

/// Extract tagged field from ASN.1 SEQUENCE
/// Returns (value_bytes, remaining_bytes)
fn extract_tagged_field<'a>(data: &'a [u8], expected_tag: u8) -> Result<(&'a [u8], &'a [u8])> {
    let (tag, length, header_size) = parse_der_tag_length(data)?;

    if tag != expected_tag {
        return Err(KerberosError::ParseError(format!(
            "Expected tag 0x{:02x}, found 0x{:02x}",
            expected_tag, tag
        )));
    }

    if data.len() < header_size + length {
        return Err(KerberosError::ParseError(
            "Incomplete tagged field".to_string(),
        ));
    }

    let value = &data[header_size..header_size + length];
    let remaining = &data[header_size + length..];

    Ok((value, remaining))
}

impl KerberosContext {
    /// The RFC 4121 per-message token machinery for this context.
    ///
    /// Keyed on [`Self::base_key`] — the §2 selection — and fixed to
    /// `Role::Acceptor` with `acceptor_subkey = false`, because this is a
    /// server and it asserts no subkey of its own. Both of those feed the
    /// Flags octet, which is inside every checksum, so getting either
    /// wrong changes every token on the wire.
    pub fn per_message_tokens(
        &self,
    ) -> Result<crate::token::PerMessageTokens<crate::token::ContextKey>> {
        let key = crate::token::ContextKey::new(self.base_key_enctype as i32, &self.base_key)
            .map_err(|e| KerberosError::DecryptionFailed(e.to_string()))?;
        Ok(crate::token::PerMessageTokens::new(
            key,
            crate::token::Role::Acceptor,
            false,
        ))
    }

    /// Accept a GSS-API Kerberos AP-REQ token with FULL CRYPTOGRAPHY
    ///
    /// This implements complete Kerberos crypto:
    /// 1. Parse GSS-API wrapper and extract AP-REQ
    /// 2. Decrypt ticket with service key
    /// 3. Extract session key from ticket
    /// 4. Decrypt and validate authenticator
    /// 5. Generate cryptographically valid AP-REP
    pub fn accept_token(keytab: &Keytab, token: &[u8]) -> Result<(Self, Vec<u8>)> {
        Self::accept_token_with_skew(keytab, token, DEFAULT_CLOCK_SKEW_SECS)
    }

    /// As [`Self::accept_token`], with an explicit clock-skew tolerance.
    ///
    /// Exists because the interop fixtures are recorded, not live: a
    /// captured AP-REQ is minutes or months old by the time it is
    /// replayed in a test, and a fixture that expires is a test that
    /// rots. It is also how a caller applies its own site policy;
    /// `accept_token` uses [`DEFAULT_CLOCK_SKEW_SECS`] (300, the RFC 4120
    /// §5.3 recommendation).
    pub fn accept_token_with_skew(
        keytab: &Keytab,
        token: &[u8],
        max_skew_secs: i64,
    ) -> Result<(Self, Vec<u8>)> {
        Self::accept_token_at(keytab, token, max_skew_secs, current_time())
    }

    /// As [`Self::accept_token_with_skew`], with the clock supplied.
    ///
    /// Ticket expiry cannot be tested against a live clock without a test
    /// that rots: a fixture recorded today is valid today and expired
    /// tomorrow, so the assertion would flip on its own. Injecting `now`
    /// makes "this real MIT ticket is refused once its endtime has
    /// passed" a deterministic statement about a committed fixture.
    pub(crate) fn accept_token_at(
        keytab: &Keytab,
        token: &[u8],
        max_skew_secs: i64,
        now: i64,
    ) -> Result<(Self, Vec<u8>)> {
        info!(
            "🔐 Accepting Kerberos GSS token with FULL CRYPTOGRAPHY: {} bytes",
            token.len()
        );

        // Parse GSS-API wrapper
        if token.len() < 20 {
            return Err(KerberosError::ParseError("Token too short".to_string()));
        }

        // Verify GSS-API APPLICATION tag [0x60]
        if token[0] != 0x60 {
            return Err(KerberosError::ParseError(format!(
                "Expected GSS APPLICATION tag 0x60, found 0x{:02x}",
                token[0]
            )));
        }

        // Parse length
        let (_total_len, len_bytes) = parse_der_length(&token[1..])?;
        let gss_content_start = 1 + len_bytes;

        // Verify Kerberos OID (1.2.840.113554.1.2.2)
        let krb5_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        if token.len() < gss_content_start + krb5_oid.len() {
            return Err(KerberosError::ParseError(
                "Token too short for OID".to_string(),
            ));
        }

        if &token[gss_content_start..gss_content_start + krb5_oid.len()] != &krb5_oid {
            return Err(KerberosError::ParseError(
                "Not a Kerberos GSS token".to_string(),
            ));
        }

        // RFC 4121 §4.1: between the mech OID and the Kerberos message
        // sits a 2-octet TOK_ID — 01 00 for AP-REQ, 02 00 for AP-REP,
        // 03 00 for KRB-ERROR.
        //
        // This was skipped over: the parser jumped straight from the OID
        // to the message and then rejected the leading 0x01 as a bad
        // AP-REQ tag. NOTHING CAUGHT IT because no real GSS token was
        // ever fed to this function — the only fixtures were hand-built
        // ones that omitted the field, so the parser and its tests agreed
        // with each other and with no other implementation.
        let tok_id_start = gss_content_start + krb5_oid.len();
        if token.len() < tok_id_start + 2 {
            return Err(KerberosError::ParseError(
                "Token too short for TOK_ID".to_string(),
            ));
        }
        let tok_id = &token[tok_id_start..tok_id_start + 2];
        if tok_id != TOK_ID_AP_REQ {
            return Err(KerberosError::ParseError(format!(
                "Expected TOK_ID 01 00 (KRB_AP_REQ), found {:02x} {:02x}",
                tok_id[0], tok_id[1]
            )));
        }

        // Extract AP-REQ (after OID and TOK_ID)
        let ap_req_start = tok_id_start + 2;
        let ap_req_data = &token[ap_req_start..];

        debug!(
            "   Parsed GSS wrapper: AP-REQ is {} bytes",
            ap_req_data.len()
        );

        // Parse AP-REQ structure
        let (ticket, enc_authenticator, ap_options) = Self::parse_ap_req(ap_req_data)?;

        // Find service key for this ticket
        let service_name = ticket.sname.join("/");
        // Select by the enctype the TICKET declares, not just the name.
        let service_key = keytab
            .find_key_for(&service_name, ticket.enc_part.enctype, ticket.enc_part.kvno)
            .ok_or_else(|| {
                KerberosError::PrincipalNotFound(format!(
                    "{} with enctype {:?}",
                    service_name, ticket.enc_part.enctype
                ))
            })?;

        info!(
            "   Found service key: {}@{}",
            service_key.principal, service_key.realm
        );

        // Decrypt ticket to get session key
        let enc_ticket_part = ticket.decrypt(service_key)?;

        // BEFORE the authenticator: a ticket outside its validity window
        // is not a skew problem and must not be reported as one.
        enc_ticket_part.validate_validity(now, max_skew_secs)?;

        let session_key = enc_ticket_part.key;

        info!(
            "   ✅ Ticket decrypted, extracted session key: {} bytes",
            session_key.key.len()
        );

        // Decrypt and validate authenticator
        let authenticator = Authenticator::parse_and_decrypt(&enc_authenticator, &session_key)?;
        authenticator.validate(now, max_skew_secs)?;

        info!(
            "   ✅ Authenticator validated: time_skew={}s",
            current_time() - authenticator.ctime
        );

        // Create context
        let client_name = enc_ticket_part.cname.join("/");
        // RFC 4121 §2 base-key selection. This server asserts no acceptor
        // subkey (see `generate_ap_rep_with_crypto`, which passes None), so
        // the choice is between the initiator's subkey and the ticket
        // session key — and until now it was always the latter.
        let (base_key, base_key_enctype, used_initiator_subkey) =
            select_base_key(&session_key, authenticator.subkey.as_ref());
        if used_initiator_subkey {
            info!("   Adopting the initiator's subkey as the per-message base key");
        }

        let context = KerberosContext {
            client_principal: format!("{}@{}", client_name, enc_ticket_part.crealm),
            service_principal: format!("{}@{}", service_name, service_key.realm),
            session_key: session_key.key.clone(),
            enctype: session_key.enctype,
            established: true,
            client_realm: enc_ticket_part.crealm,
            base_key,
            base_key_enctype,
            used_initiator_subkey,
        };

        // RFC 4120 §3.2.4: an AP-REP is the answer to MUTUAL-REQUIRED and
        // to nothing else. Sending one unasked breaks the initiator, which
        // is already established and rejects the extra token.
        let ap_rep = if ap_options & AP_OPTS_MUTUAL_REQUIRED != 0 {
            Self::generate_ap_rep_with_crypto(
                &session_key,
                authenticator.ctime,
                authenticator.cusec,
            )?
        } else {
            debug!("   No MUTUAL-REQUIRED in ap-options — replying with an empty token");
            Vec::new()
        };

        info!(
            "✅ FULL CRYPTO: Kerberos context established: client={}",
            context.client_principal
        );
        info!(
            "   Session key: {} bytes, enctype={:?}",
            context.session_key.len(),
            context.enctype
        );
        debug!("   Generated encrypted AP-REP: {} bytes", ap_rep.len());

        Ok((context, ap_rep))
    }

    /// Parse AP-REQ and extract ticket + encrypted authenticator
    fn parse_ap_req(data: &[u8]) -> Result<(Ticket, Vec<u8>, u32)> {
        // AP-REQ ::= [APPLICATION 14] SEQUENCE {
        //   pvno[0] INTEGER (5),
        //   msg-type[1] INTEGER (14),
        //   ap-options[2] APOptions,
        //   ticket[3] Ticket,
        //   authenticator[4] EncryptedData
        // }

        let (tag, _ap_req_len, ap_req_header) = parse_der_tag_length(data)?;
        if tag != 0x6E {
            // APPLICATION 14
            return Err(KerberosError::ParseError(format!(
                "Expected AP-REQ tag 0x6E, found 0x{:02x}",
                tag
            )));
        }

        let ap_req_content = &data[ap_req_header..];

        // Parse inner SEQUENCE
        let (seq_tag, _seq_len, seq_header) = parse_der_tag_length(ap_req_content)?;
        if seq_tag != 0x30 {
            return Err(KerberosError::ParseError(
                "Expected SEQUENCE in AP-REQ".to_string(),
            ));
        }

        let content = &ap_req_content[seq_header..];

        // Parse pvno[0]
        let (vno_data, mut remaining) = extract_tagged_field(content, 0xA0)?;
        let vno = parse_asn1_integer(vno_data)?;
        if vno != 5 {
            return Err(KerberosError::ParseError(format!(
                "Expected pvno=5, got {}",
                vno
            )));
        }

        // Parse msg-type[1]
        let (msg_type_data, rest) = extract_tagged_field(remaining, 0xA1)?;
        let msg_type = parse_asn1_integer(msg_type_data)?;
        if msg_type != 14 {
            return Err(KerberosError::ParseError(format!(
                "Expected msg-type=14 (AP-REQ), got {}",
                msg_type
            )));
        }
        remaining = rest;

        // ap-options[2] — NOT skippable.
        //
        // RFC 4120 §3.2.4: the AP-REP is sent ONLY when MUTUAL-REQUIRED is
        // set. This discarded the field and replied with an AP-REP every
        // time, so a client that did not ask for mutual authentication —
        // which is already complete after sending its AP-REQ — got a token
        // it had no use for, fed it to GSS anyway, and was told
        // "Context is already fully established". libtirpc then abandons
        // the context with no GSS error of its own, which is precisely
        // how `mount -o sec=krb5p` failed with a bare "access denied".
        let (opts_data, rest) = extract_tagged_field(remaining, 0xA2)?;
        let ap_options = parse_asn1_bit_string(opts_data)?;
        remaining = rest;

        // Parse ticket[3]
        let (ticket_data, rest) = extract_tagged_field(remaining, 0xA3)?;
        let ticket = Ticket::parse(ticket_data)?;
        remaining = rest;

        debug!(
            "   Parsed ticket: realm={}, sname={}",
            ticket.realm,
            ticket.sname.join("/")
        );

        // Parse authenticator[4] (EncryptedData)
        let (auth_data, _) = extract_tagged_field(remaining, 0xA4)?;
        let enc_auth = EncryptedData::parse(auth_data)?;

        debug!(
            "   Parsed encrypted authenticator: {} bytes, ap_options=0x{:08x}{}",
            enc_auth.cipher.len(),
            ap_options,
            if ap_options & AP_OPTS_MUTUAL_REQUIRED != 0 {
                " (MUTUAL-REQUIRED)"
            } else {
                ""
            }
        );

        Ok((ticket, enc_auth.cipher, ap_options))
    }

    /// Generate properly encrypted AP-REP with real cryptography
    fn generate_ap_rep_with_crypto(
        session_key: &SessionKey,
        ctime: i64,
        cusec: u32,
    ) -> Result<Vec<u8>> {
        debug!("   Generating AP-REP with encryption");

        // Create encrypted AP-REP part
        let enc_part = EncAPRepPart::create(ctime, cusec, None);
        let encrypted = enc_part.encrypt(session_key)?;

        // Build AP-REP: [APPLICATION 15] SEQUENCE {
        //   pvno[0] INTEGER (5),
        //   msg-type[1] INTEGER (15),
        //   enc-part[2] EncryptedData
        // }
        let mut ap_rep_content = Vec::new();

        // pvno[0] = 5
        ap_rep_content.push(0xA0);
        ap_rep_content.push(0x03);
        ap_rep_content.push(0x02);
        ap_rep_content.push(0x01);
        ap_rep_content.push(0x05);

        // msg-type[1] = 15
        ap_rep_content.push(0xA1);
        ap_rep_content.push(0x03);
        ap_rep_content.push(0x02);
        ap_rep_content.push(0x01);
        ap_rep_content.push(0x0F);

        // enc-part[2]
        ap_rep_content.push(0xA2);
        Self::encode_length(&mut ap_rep_content, encrypted.len());
        ap_rep_content.extend_from_slice(&encrypted);

        // Wrap in SEQUENCE
        let mut ap_rep_seq = vec![0x30];
        Self::encode_length(&mut ap_rep_seq, ap_rep_content.len());
        ap_rep_seq.extend_from_slice(&ap_rep_content);

        // Wrap in APPLICATION 15
        let mut ap_rep = vec![0x6F];
        Self::encode_length(&mut ap_rep, ap_rep_seq.len());
        ap_rep.extend_from_slice(&ap_rep_seq);

        // Wrap in GSS-API. The TOK_ID (RFC 4121 §4.1) is NOT optional —
        // an initiator reading this reply expects 02 00 before the
        // AP-REP, and the emitter omitted it for the same reason the
        // parser ignored it on the way in.
        let krb5_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let gss_content_len = krb5_oid.len() + TOK_ID_AP_REP.len() + ap_rep.len();

        let mut token = vec![0x60]; // APPLICATION 0
        Self::encode_length(&mut token, gss_content_len);
        token.extend_from_slice(&krb5_oid);
        token.extend_from_slice(TOK_ID_AP_REP);
        token.extend_from_slice(&ap_rep);

        debug!("   Generated AP-REP: {} bytes (encrypted)", token.len());
        Ok(token)
    }

    /// Generate a minimal valid AP-REP token wrapped in GSS-API framing
    ///
    /// Structure:
    /// - GSS-API Application tag [0x60]
    /// - GSS OID for Kerberos (1.2.840.113554.1.2.2)
    /// - Kerberos AP-REP message
    #[allow(dead_code)]
    fn generate_ap_rep_token() -> Result<Vec<u8>> {
        let mut token = Vec::new();

        // Kerberos OID: 1.2.840.113554.1.2.2 (RFC 1964)
        let krb5_oid = vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];

        // Generate minimal AP-REP (Application tag 15)
        // AP-REP ::= [APPLICATION 15] SEQUENCE {
        //   pvno[0] INTEGER (5),
        //   msg-type[1] INTEGER (15),  -- AP-REP
        //   enc-part[2] EncryptedData  -- minimal placeholder
        // }
        let ap_rep_inner = Self::encode_ap_rep_inner();

        // Wrap in APPLICATION 15 tag
        let mut ap_rep = Vec::new();
        ap_rep.push(0x6F); // APPLICATION 15
        Self::encode_length(&mut ap_rep, ap_rep_inner.len());
        ap_rep.extend_from_slice(&ap_rep_inner);

        // Calculate total length for GSS wrapper
        let gss_content_len = krb5_oid.len() + TOK_ID_AP_REP.len() + ap_rep.len();

        // GSS-API wrapper: APPLICATION 0 (0x60)
        token.push(0x60);
        Self::encode_length(&mut token, gss_content_len);
        token.extend_from_slice(&krb5_oid);
        token.extend_from_slice(TOK_ID_AP_REP);
        token.extend_from_slice(&ap_rep);

        debug!("Generated GSS-wrapped AP-REP: {} bytes", token.len());
        Ok(token)
    }

    /// Encode the inner AP-REP structure
    #[allow(dead_code)]
    fn encode_ap_rep_inner() -> Vec<u8> {
        let mut inner = Vec::new();

        // SEQUENCE
        let mut seq = Vec::new();

        // pvno[0] INTEGER (5)
        seq.push(0xA0); // Context tag 0
        seq.push(0x03); // Length
        seq.push(0x02); // INTEGER
        seq.push(0x01); // Length 1
        seq.push(0x05); // Value: 5

        // msg-type[1] INTEGER (15 = AP-REP)
        seq.push(0xA1); // Context tag 1
        seq.push(0x03); // Length
        seq.push(0x02); // INTEGER
        seq.push(0x01); // Length 1
        seq.push(0x0F); // Value: 15

        // enc-part[2] EncryptedData (minimal placeholder)
        // EncryptedData ::= SEQUENCE {
        //   etype[0] INTEGER,
        //   kvno[1] INTEGER OPTIONAL,
        //   cipher[2] OCTET STRING
        // }
        let mut enc_part = Vec::new();

        // etype[0] = 18 (AES256-CTS-HMAC-SHA1-96)
        enc_part.push(0xA0); // Context tag 0
        enc_part.push(0x03); // Length
        enc_part.push(0x02); // INTEGER
        enc_part.push(0x01); // Length 1
        enc_part.push(0x12); // Value: 18

        // cipher[2] = empty octet string (placeholder - would be encrypted in production)
        enc_part.push(0xA2); // Context tag 2
        enc_part.push(0x11); // Length (17 bytes for the OCTET STRING structure + 15 bytes data)
        enc_part.push(0x04); // OCTET STRING
        enc_part.push(0x0F); // Length (15 bytes of dummy encrypted data)
        enc_part.extend_from_slice(&[0u8; 15]); // Placeholder encrypted data

        // Wrap enc_part in SEQUENCE
        let mut enc_part_seq = Vec::new();
        enc_part_seq.push(0x30); // SEQUENCE
        Self::encode_length(&mut enc_part_seq, enc_part.len());
        enc_part_seq.extend_from_slice(&enc_part);

        // Add enc-part to main sequence with context tag 2
        seq.push(0xA2); // Context tag 2
        Self::encode_length(&mut seq, enc_part_seq.len());
        seq.extend_from_slice(&enc_part_seq);

        // Wrap everything in SEQUENCE
        inner.push(0x30); // SEQUENCE
        Self::encode_length(&mut inner, seq.len());
        inner.extend_from_slice(&seq);

        inner
    }

    /// Encode ASN.1 DER length
    fn encode_length(output: &mut Vec<u8>, length: usize) {
        if length < 128 {
            output.push(length as u8);
        } else if length < 256 {
            output.push(0x81); // Long form, 1 byte
            output.push(length as u8);
        } else {
            output.push(0x82); // Long form, 2 bytes
            output.push((length >> 8) as u8);
            output.push((length & 0xFF) as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enctype_conversion() {
        assert_eq!(EncType::from_i32(17), Some(EncType::AES128CtsHmacSha196));
        assert_eq!(EncType::from_i32(18), Some(EncType::AES256CtsHmacSha196));
        assert_eq!(EncType::from_i32(19), Some(EncType::AES128CtsHmacSha256128));
        assert_eq!(EncType::from_i32(20), Some(EncType::AES256CtsHmacSha384192));
        assert_eq!(EncType::from_i32(999), None);
    }

    #[test]
    fn test_encode_length_short() {
        let mut output = Vec::new();
        KerberosContext::encode_length(&mut output, 42);
        assert_eq!(output, vec![42]);
    }

    #[test]
    fn test_encode_length_long_1byte() {
        let mut output = Vec::new();
        KerberosContext::encode_length(&mut output, 200);
        assert_eq!(output, vec![0x81, 200]);
    }

    #[test]
    fn test_encode_length_long_2bytes() {
        let mut output = Vec::new();
        KerberosContext::encode_length(&mut output, 300);
        assert_eq!(output, vec![0x82, 0x01, 0x2C]); // 0x012C = 300
    }

    #[test]
    fn test_ap_rep_structure() {
        // Test that AP-REP generation doesn't panic
        let result = KerberosContext::generate_ap_rep_token();
        assert!(result.is_ok());

        let token = result.unwrap();

        // Verify it's not empty
        assert!(token.len() > 20, "AP-REP token should be substantial");

        // Verify GSS-API wrapper (APPLICATION 0)
        assert_eq!(token[0], 0x60, "Should start with GSS APPLICATION tag");

        // Token should contain Kerberos OID
        assert!(token.len() > 15, "Should have room for OID and AP-REP");
    }

    #[test]
    fn test_ap_rep_contains_krb5_oid() {
        let token = KerberosContext::generate_ap_rep_token().unwrap();

        // Kerberos OID: 1.2.840.113554.1.2.2
        // In DER: 06 09 2a 86 48 86 f7 12 01 02 02
        let krb5_oid = vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];

        // Check if the OID appears in the token
        assert!(
            token
                .windows(krb5_oid.len())
                .any(|window| window == krb5_oid.as_slice()),
            "AP-REP should contain Kerberos OID"
        );
    }

    #[test]
    fn test_is_leap_year() {
        // Regular leap years (divisible by 4)
        assert!(is_leap_year(2020));
        assert!(is_leap_year(2024));

        // Not leap years
        assert!(!is_leap_year(2021));
        assert!(!is_leap_year(2022));
        assert!(!is_leap_year(2023));

        // Century years (divisible by 100 but not 400)
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2100));

        // Century years (divisible by 400)
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2400));
    }

    #[test]
    fn test_calculate_unix_timestamp_epoch() {
        // Unix epoch: 1970-01-01 00:00:00 UTC = 0
        let ts = calculate_unix_timestamp(1970, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_calculate_unix_timestamp_known_dates() {
        // 2000-01-01 00:00:00 UTC = 946684800
        let ts = calculate_unix_timestamp(2000, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(ts, 946684800);

        // 2020-01-01 12:00:00 UTC = 1577880000
        let ts = calculate_unix_timestamp(2020, 1, 1, 12, 0, 0).unwrap();
        assert_eq!(ts, 1577880000);

        // 2024-12-31 23:59:59 UTC (leap year)
        let ts = calculate_unix_timestamp(2024, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(ts, 1735689599);
    }

    #[test]
    fn test_calculate_unix_timestamp_leap_year() {
        // Feb 29, 2020 (leap year)
        let ts_feb29 = calculate_unix_timestamp(2020, 2, 29, 0, 0, 0).unwrap();
        let ts_mar01 = calculate_unix_timestamp(2020, 3, 1, 0, 0, 0).unwrap();

        // Should be exactly 1 day apart
        assert_eq!(ts_mar01 - ts_feb29, 86400);
    }

    #[test]
    fn test_parse_digits() {
        assert_eq!(parse_digits("2024", "year").unwrap(), 2024);
        assert_eq!(parse_digits("12", "month").unwrap(), 12);
        assert_eq!(parse_digits("01", "day").unwrap(), 1);
        assert_eq!(parse_digits("00", "hour").unwrap(), 0);

        // Invalid
        assert!(parse_digits("abc", "test").is_err());
        assert!(parse_digits("", "test").is_err());
    }

    #[test]
    fn test_parse_kerberos_time_valid() {
        // Create a GeneralizedTime: "20240101120000Z" (2024-01-01 12:00:00 UTC)
        let time_str = b"20240101120000Z";
        let mut data = vec![0x18]; // GeneralizedTime tag
        data.push(time_str.len() as u8); // Length
        data.extend_from_slice(time_str);

        let ts = parse_kerberos_time(&data).unwrap();

        // Verify it's a reasonable timestamp (after 2024-01-01 00:00:00)
        assert!(ts > 1704067200); // 2024-01-01 00:00:00 UTC
        assert!(ts < 1704153600); // 2024-01-02 00:00:00 UTC
    }

    #[test]
    fn test_parse_kerberos_time_epoch() {
        // Unix epoch: "19700101000000Z"
        let time_str = b"19700101000000Z";
        let mut data = vec![0x18]; // GeneralizedTime tag
        data.push(time_str.len() as u8); // Length
        data.extend_from_slice(time_str);

        let ts = parse_kerberos_time(&data).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_parse_kerberos_time_year_2000() {
        // "20000101000000Z" (Y2K)
        let time_str = b"20000101000000Z";
        let mut data = vec![0x18];
        data.push(time_str.len() as u8);
        data.extend_from_slice(time_str);

        let ts = parse_kerberos_time(&data).unwrap();
        assert_eq!(ts, 946684800);
    }

    #[test]
    fn test_parse_kerberos_time_invalid_tag() {
        // Wrong tag (not 0x18)
        let time_str = b"20240101120000Z";
        let mut data = vec![0x17]; // Wrong tag
        data.push(time_str.len() as u8);
        data.extend_from_slice(time_str);

        assert!(parse_kerberos_time(&data).is_err());
    }

    #[test]
    fn test_parse_kerberos_time_invalid_format() {
        // Too short
        let time_str = b"202401Z";
        let mut data = vec![0x18];
        data.push(time_str.len() as u8);
        data.extend_from_slice(time_str);

        assert!(parse_kerberos_time(&data).is_err());
    }

    #[test]
    fn test_parse_kerberos_time_invalid_month() {
        // Month = 13 (invalid)
        let time_str = b"20241301120000Z";
        let mut data = vec![0x18];
        data.push(time_str.len() as u8);
        data.extend_from_slice(time_str);

        assert!(parse_kerberos_time(&data).is_err());
    }

    #[test]
    fn test_parse_kerberos_time_lowercase_z() {
        // Lowercase 'z' should also work
        let time_str = b"20240101120000z";
        let mut data = vec![0x18];
        data.push(time_str.len() as u8);
        data.extend_from_slice(time_str);

        assert!(parse_kerberos_time(&data).is_ok());
    }

    #[test]
    fn test_ap_rep_has_application_tag() {
        let token = KerberosContext::generate_ap_rep_token().unwrap();

        // Find the AP-REP application tag (0x6F = APPLICATION 15)
        assert!(
            token.contains(&0x6F),
            "Should contain APPLICATION 15 tag for AP-REP"
        );
    }

    #[test]
    fn test_keytab_invalid_version() {
        // Keytab with invalid version
        let data = vec![0x05, 0x01]; // Version 0x0501 (invalid)
        let result = Keytab::parse(&data);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Unsupported keytab version"));
    }

    #[test]
    fn test_keytab_empty() {
        let data = vec![];
        let result = Keytab::parse(&data);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_keytab_correct_version() {
        // Minimal keytab with correct version but no entries
        let data = vec![0x05, 0x02]; // Version 0x0502 (correct)
        let result = Keytab::parse(&data);
        assert!(result.is_ok());
        let keytab = result.unwrap();
        assert_eq!(keytab.keys().len(), 0);
    }

    #[test]
    fn a_multi_enctype_keytab_selects_by_the_tickets_enctype() {
        // THE ORDINARY SHAPE OF A REAL KEYTAB: `ktadd` writes one key per
        // enctype for the same principal. Matching on the name alone and
        // taking the first hit picks an arbitrary enctype, and the ticket
        // then fails its integrity check with an HMAC mismatch that reads
        // exactly like a wrong password.
        //
        // Measured against a live MIT KDC on 2026-08-27: four keys for
        // nfs/flintsrv.flint.test, `find_key` took the wrong one, and
        // every real `mount -o sec=krb5p` failed. The interop fixtures
        // missed it because they gave each enctype its OWN principal, so
        // every keytab in those tests held exactly one key.
        let mk = |etype, kvno, byte| ServiceKey {
            principal: "nfs/srv".to_string(),
            realm: "EXAMPLE.COM".to_string(),
            kvno,
            enctype: etype,
            key: vec![byte; 32],
        };
        let keytab = Keytab {
            keys: vec![
                mk(EncType::AES256CtsHmacSha384192, 2, 0xAA),
                mk(EncType::AES256CtsHmacSha196, 2, 0xBB),
                mk(EncType::AES128CtsHmacSha256128, 2, 0xCC),
                mk(EncType::AES128CtsHmacSha196, 2, 0xDD),
            ],
        };

        // Every enctype must select ITS OWN key, not the first entry.
        for (etype, want) in [
            (EncType::AES256CtsHmacSha384192, 0xAAu8),
            (EncType::AES256CtsHmacSha196, 0xBB),
            (EncType::AES128CtsHmacSha256128, 0xCC),
            (EncType::AES128CtsHmacSha196, 0xDD),
        ] {
            let k = keytab
                .find_key_for("nfs/srv", etype, None)
                .unwrap_or_else(|| panic!("{etype:?} not found"));
            assert_eq!(k.enctype, etype);
            assert_eq!(k.key[0], want, "{etype:?} selected the wrong key");
        }

        // Realm-qualified name resolves the same way.
        assert_eq!(
            keytab
                .find_key_for("nfs/srv@EXAMPLE.COM", EncType::AES256CtsHmacSha196, None)
                .unwrap()
                .key[0],
            0xBB
        );

        // An enctype the keytab does not carry is None, not a wrong key —
        // the failure mode that produced the HMAC mismatch.
        let one = Keytab {
            keys: vec![mk(EncType::AES256CtsHmacSha196, 2, 0xBB)],
        };
        assert!(
            one.find_key_for("nfs/srv", EncType::AES128CtsHmacSha196, None)
                .is_none()
        );

        // kvno picks among same-enctype keys when it matches, and is not
        // fatal when it does not (a keytab mid-rotation carries the old one).
        let rot = Keytab {
            keys: vec![
                mk(EncType::AES256CtsHmacSha196, 3, 0x11),
                mk(EncType::AES256CtsHmacSha196, 4, 0x22),
            ],
        };
        assert_eq!(
            rot.find_key_for("nfs/srv", EncType::AES256CtsHmacSha196, Some(4))
                .unwrap()
                .key[0],
            0x22
        );
        assert!(
            rot.find_key_for("nfs/srv", EncType::AES256CtsHmacSha196, Some(99))
                .is_some()
        );
    }

    #[test]
    fn test_service_key_find() {
        let key1 = ServiceKey {
            principal: "nfs/server".to_string(),
            realm: "EXAMPLE.COM".to_string(),
            kvno: 1,
            enctype: EncType::AES256CtsHmacSha196,
            key: vec![1, 2, 3, 4],
        };

        let key2 = ServiceKey {
            principal: "host/server".to_string(),
            realm: "EXAMPLE.COM".to_string(),
            kvno: 2,
            enctype: EncType::AES128CtsHmacSha196,
            key: vec![5, 6, 7, 8],
        };

        let keytab = Keytab {
            keys: vec![key1, key2],
        };

        // Test exact match
        assert!(keytab.find_key("nfs/server").is_some());
        assert!(keytab.find_key("host/server").is_some());

        // Test full principal with realm
        assert!(keytab.find_key("nfs/server@EXAMPLE.COM").is_some());

        // Test not found
        assert!(keytab.find_key("http/server").is_none());
    }

    #[test]
    fn test_kerberos_context_accept_token() {
        // Test with minimal keytab
        let keytab = Keytab { keys: Vec::new() };

        // Test with a minimal token (not a real AP-REQ)
        let token = vec![
            0x60, 0x10, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];

        let result = KerberosContext::accept_token(&keytab, &token);

        // Should fail because it's not a valid AP-REQ with full crypto parsing
        assert!(result.is_err(), "Should fail on invalid token");
        // Error could be parsing error or incomplete data
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Parse")
                || err_msg.contains("too short")
                || err_msg.contains("Incomplete"),
            "Expected parsing error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_kerberos_context_reject_short_token() {
        let keytab = Keytab { keys: Vec::new() };
        let token = vec![0x60]; // Too short

        let result = KerberosContext::accept_token(&keytab, &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    //==========================================================================
    // PHASE 8: COMPREHENSIVE CRYPTO TESTS
    //==========================================================================

    #[test]
    fn test_parse_asn1_integer() {
        // INTEGER 42 = 02 01 2A
        let data = vec![0x02, 0x01, 0x2A];
        let result = parse_asn1_integer(&data).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_parse_asn1_octet_string() {
        // OCTET STRING "hello" = 04 05 68 65 6C 6C 6F
        let data = vec![0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        let result = parse_asn1_octet_string(&data).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_parse_asn1_general_string() {
        // GeneralString "test" = 1B 04 74 65 73 74
        let data = vec![0x1B, 0x04, 0x74, 0x65, 0x73, 0x74];
        let result = parse_asn1_general_string(&data).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn integers_whose_top_bit_is_set_keep_their_zero_octet() {
        assert_eq!(encode_asn1_integer(200), [0x02, 0x02, 0x00, 0xC8]);
        assert_eq!(encode_asn1_integer(40_000), [0x02, 0x03, 0x00, 0x9C, 0x40]);
        assert_eq!(encode_asn1_integer(127), [0x02, 0x01, 0x7F]);
        assert_eq!(encode_asn1_integer(0), [0x02, 0x01, 0x00]);
        for cusec in [
            0, 127, 128, 200, 255, 256, 32_767, 32_768, 40_000, 65_535, 999_999,
        ] {
            assert_eq!(
                parse_asn1_integer(&encode_asn1_integer(cusec)).unwrap(),
                cusec
            );
        }
    }

    /// The AP-REP must echo cusec exactly, including values whose DER
    /// encoding needs a leading zero octet.
    #[test]
    fn the_ap_rep_echoes_every_cusec_exactly() {
        for cusec in [128u32, 200, 255, 32_768, 65_535] {
            let part = EncAPRepPart::create(1_790_000_000, cusec, None).encode_asn1();
            let f = crate::der::Fields::parse_tagged("EncAPRepPart", 0x7B, &part).unwrap();
            assert_eq!(f.get(1).unwrap().u32().unwrap(), cusec);
        }
    }

    #[test]
    fn test_encode_asn1_integer() {
        let encoded = encode_asn1_integer(42);
        // Should be: 02 01 2A
        assert_eq!(encoded[0], 0x02); // INTEGER tag
        assert_eq!(encoded[1], 0x01); // Length 1
        assert_eq!(encoded[2], 0x2A); // Value 42
    }

    #[test]
    fn test_encode_asn1_octet_string() {
        let encoded = encode_asn1_octet_string(b"hello");
        assert_eq!(encoded[0], 0x04); // OCTET STRING tag
        assert_eq!(encoded[1], 0x05); // Length 5
        assert_eq!(&encoded[2..], b"hello");
    }

    #[test]
    fn test_encrypted_data_parse_encode() {
        let original = EncryptedData {
            enctype: EncType::AES128CtsHmacSha196,
            kvno: Some(1),
            cipher: vec![1, 2, 3, 4, 5],
        };

        let encoded = original.encode();
        let parsed = EncryptedData::parse(&encoded).unwrap();

        assert_eq!(parsed.enctype as i32, original.enctype as i32);
        assert_eq!(parsed.kvno, original.kvno);
        assert_eq!(parsed.cipher, original.cipher);
    }

    #[test]
    fn test_session_key_parse_encode() {
        let original = SessionKey {
            enctype: EncType::AES256CtsHmacSha196,
            key: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let encoded = encode_encryption_key(&original);
        let parsed = parse_encryption_key(&encoded).unwrap();

        assert_eq!(parsed.enctype as i32, original.enctype as i32);
        assert_eq!(parsed.key, original.key);
    }

    #[test]
    fn test_enc_ap_rep_part_create() {
        let enc_part = EncAPRepPart::create(12345, 67890, None);

        assert_eq!(enc_part.ctime, 12345);
        assert_eq!(enc_part.cusec, 67890);
        assert!(enc_part.subkey.is_none());
        assert_eq!(enc_part.seq_number, Some(0));
    }

    /// A ticket whose validity interval is under test directly -- the
    /// recorded interop fixtures can only exercise `endtime`, since their
    /// flags and starttime are whatever MIT chose on the day.
    fn ticket_at(flags: u32, starttime: Option<i64>, endtime: i64) -> EncTicketPart {
        EncTicketPart {
            flags,
            key: SessionKey {
                enctype: EncType::AES256CtsHmacSha196,
                key: vec![0u8; 32],
            },
            crealm: "FLINT.TEST".to_string(),
            cname: vec!["testuser".to_string()],
            authtime: 1_000,
            starttime,
            endtime,
        }
    }

    #[test]
    fn a_ticket_inside_its_window_validates() {
        assert!(
            ticket_at(0, Some(1_000), 2_000)
                .validate_validity(1_500, 300)
                .is_ok()
        );
    }

    #[test]
    fn an_expired_ticket_is_refused_and_the_tolerance_is_the_only_reprieve() {
        let t = ticket_at(0, Some(1_000), 2_000);
        // 100s past endtime, inside a 300s skew allowance: still good.
        assert!(t.validate_validity(2_100, 300).is_ok());
        // 400s past: gone.
        let err = t.validate_validity(2_400, 300).unwrap_err().to_string();
        assert!(err.contains("ticket expired"), "{err}");
    }

    #[test]
    fn a_ticket_presented_before_its_starttime_is_refused() {
        let t = ticket_at(0, Some(5_000), 9_000);
        let err = t.validate_validity(4_000, 300).unwrap_err().to_string();
        assert!(err.contains("not valid until"), "{err}");
        // and the same allowance applies at this edge
        assert!(t.validate_validity(4_800, 300).is_ok());
    }

    #[test]
    fn a_ticket_with_no_starttime_is_judged_on_endtime_alone() {
        assert!(ticket_at(0, None, 2_000).validate_validity(1, 300).is_ok());
    }

    /// RFC 4120 §3.2.3 -- INVALID beats the clock: a postdated ticket that
    /// was never validated must be refused even mid-window.
    #[test]
    fn an_invalid_flagged_ticket_is_refused_even_inside_its_window() {
        let t = ticket_at(TICKET_FLAG_INVALID, Some(1_000), 2_000);
        let err = t.validate_validity(1_500, 300).unwrap_err().to_string();
        assert!(err.contains("INVALID"), "{err}");
    }

    /// The flag bit is easy to get wrong: RFC 4120 numbers TicketFlags
    /// from the MOST significant bit, so `invalid` (flag 7) is u32 bit 24.
    /// Neighbouring flags must not trip the check.
    #[test]
    fn the_invalid_flag_is_bit_seven_counted_from_the_msb() {
        assert_eq!(TICKET_FLAG_INVALID, 0x0100_0000);
        for neighbour in [1u32 << 23, 1u32 << 25, 1u32 << 31, 1u32 << 22] {
            assert!(
                ticket_at(neighbour, Some(1_000), 2_000)
                    .validate_validity(1_500, 300)
                    .is_ok(),
                "flag bit {neighbour:#x} must not read as INVALID"
            );
        }
    }

    #[test]
    fn test_authenticator_validate_success() {
        let auth = Authenticator {
            crealm: "TEST.REALM".to_string(),
            cname: vec!["user".to_string()],
            cusec: 0,
            ctime: current_time(),
            subkey: None,
            seq_number: None,
        };

        let result = auth.validate(current_time(), 300);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authenticator_validate_time_skew() {
        let auth = Authenticator {
            crealm: "TEST.REALM".to_string(),
            cname: vec!["user".to_string()],
            cusec: 0,
            ctime: current_time() - 400, // 400 seconds ago
            subkey: None,
            seq_number: None,
        };

        let result = auth.validate(current_time(), 300); // 5 minute tolerance
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Time skew"));
    }

    #[test]
    fn the_initiator_subkey_becomes_the_per_message_base_key() {
        // RFC 4121 §2. The subkey was parsed and discarded, so every
        // per-message token was keyed on the session key even when the
        // client had asked for a subkey — bytes a real peer rejects,
        // with nothing on this side reporting an error.
        let session = SessionKey {
            enctype: EncType::AES256CtsHmacSha196,
            key: vec![0xAA; 32],
        };
        let subkey = SessionKey {
            enctype: EncType::AES128CtsHmacSha196,
            key: vec![0xBB; 16],
        };

        let (k, e, used) = select_base_key(&session, Some(&subkey));
        assert_eq!(k, subkey.key, "the subkey must win");
        assert_eq!(
            e,
            EncType::AES128CtsHmacSha196,
            "and it carries its OWN enctype"
        );
        assert!(used);

        // Control: with no subkey the session key is still chosen, so the
        // assertion above is the selection working and not a constant.
        let (k, e, used) = select_base_key(&session, None);
        assert_eq!(k, session.key);
        assert_eq!(e, EncType::AES256CtsHmacSha196);
        assert!(!used);
    }

    #[test]
    fn every_enctype_agrees_with_the_crypto_modules() {
        // Three enums name these four enctypes: this one (wire/keytab
        // identity), kdf::Enctype and profile::Enctype (crypto
        // parameters). They are not merged — merging would move keytab
        // parsing into the crypto layer — so their agreement is PINNED
        // here instead. A divergence is otherwise invisible until a real
        // peer rejects the bytes.
        use crate::{kdf, profile};
        for e in [
            EncType::AES128CtsHmacSha196,
            EncType::AES256CtsHmacSha196,
            EncType::AES128CtsHmacSha256128,
            EncType::AES256CtsHmacSha384192,
        ] {
            let n = e.etype();
            let k = kdf::Enctype::from_i32(n).expect("kdf knows this enctype");
            let pr = profile::Enctype::from_i32(n).expect("profile knows this enctype");
            assert_eq!(k.etype(), n, "kdf round-trips {n}");
            assert_eq!(pr.as_i32(), n, "profile round-trips {n}");
            assert_eq!(
                k.is_rfc8009(),
                pr.is_rfc8009(),
                "enctype {n}: the two modules disagree on which RFC governs it"
            );
            assert_eq!(
                k.key_size(),
                pr.ke_len(),
                "enctype {n}: base-key size and Ke length must agree"
            );
        }
        // And the naming records the truth: enctype 20 is SHA-384-192.
        assert_eq!(EncType::AES256CtsHmacSha384192.etype(), 20);
    }

    #[test]
    fn test_current_time_reasonable() {
        let time = current_time();
        // Should be a recent timestamp (after 2020-01-01)
        assert!(time > 1577836800);
        // Should be before year 2100
        assert!(time < 4102444800);
    }

    #[test]
    fn test_extract_tagged_field_success() {
        // Create test data: [A0] 03 02 01 05 (context tag 0 containing INTEGER 5)
        let data = vec![0xA0, 0x03, 0x02, 0x01, 0x05, 0xFF, 0xFF];

        let (value, remaining) = extract_tagged_field(&data, 0xA0).unwrap();
        assert_eq!(value.len(), 3);
        assert_eq!(value[0], 0x02); // INTEGER tag
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0], 0xFF);
    }

    #[test]
    fn test_extract_tagged_field_wrong_tag() {
        let data = vec![0xA0, 0x03, 0x02, 0x01, 0x05];

        let result = extract_tagged_field(&data, 0xA1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected tag"));
    }
}
