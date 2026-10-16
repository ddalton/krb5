//! The Privilege Attribute Certificate (MS-PAC): the authorization data
//! Active Directory (and MIT's KDC since 1.20) puts in tickets: who the
//! user is to Windows (SIDs, groups, logon details) and signatures binding
//! it to the ticket.
//!
//! [`Pac::parse`] reads the buffer table; typed readers decode the buffers
//! an application wants: [`Pac::logon_info`] (the NDR-encoded
//! `KERB_VALIDATION_INFO`: user and group SIDs), [`Pac::client_info`],
//! [`Pac::upn_dns_info`], [`Pac::delegation_info`] (the services an
//! S4U2Proxy ticket passed through), [`Pac::attributes`] and
//! [`Pac::requestor_sid`].
//!
//! A PAC is only worth what its signatures are. A service checks the
//! server signature with its own key and the client info against the
//! ticket, as MIT's acceptor does ([`Pac::verify_server_signature`],
//! [`Pac::verify_client`]); [`KerberosContext`](crate::KerberosContext)
//! does both and keeps only a PAC that passes. The KDC's signatures need
//! the `krbtgt` key, so only a KDC can check them
//! ([`Pac::verify_kdc_signature`], [`Pac::verify_full_signature`],
//! [`verify_ticket_signature`]).

use std::fmt;

use crate::der::{self, Fields, Reader};
use crate::key::Key;

// PAC_INFO_BUFFER ulType (MS-PAC 2.4).
/// `KERB_VALIDATION_INFO`: the user's identity and groups (MS-PAC 2.5).
pub const PAC_LOGON_INFO: u32 = 1;
/// `PAC_CREDENTIAL_INFO`: encrypted credentials from PKINIT (MS-PAC 2.6).
pub const PAC_CREDENTIALS_INFO: u32 = 2;
/// The server signature over the PAC, keyed with the service's key (MS-PAC 2.8).
pub const PAC_SERVER_CHECKSUM: u32 = 6;
/// The KDC signature over the server signature, keyed with `krbtgt` (MS-PAC 2.8).
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
/// `PAC_CLIENT_INFO`: the client's name and authtime (MS-PAC 2.7).
pub const PAC_CLIENT_INFO: u32 = 10;
/// `S4U_DELEGATION_INFO`: the services an S4U2Proxy ticket passed through (MS-PAC 2.9).
pub const PAC_DELEGATION_INFO: u32 = 11;
/// `UPN_DNS_INFO`: the UPN and DNS domain (MS-PAC 2.10).
pub const PAC_UPN_DNS_INFO: u32 = 12;
/// The client's claims (MS-PAC 2.11).
pub const PAC_CLIENT_CLAIMS: u32 = 13;
/// `PAC_DEVICE_INFO`: the device's identity and groups, for compound identity (MS-PAC 2.12).
pub const PAC_DEVICE_INFO: u32 = 14;
/// The device's claims (MS-PAC 2.13).
pub const PAC_DEVICE_CLAIMS: u32 = 15;
/// The ticket signature: the KDC's over the ticket's EncTicketPart, keyed with `krbtgt` (MS-PAC 2.8).
pub const PAC_TICKET_CHECKSUM: u32 = 16;
/// `PAC_ATTRIBUTES_INFO`: whether the PAC was requested (MS-PAC 2.14).
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
/// `PAC_REQUESTOR`: the SID of the client the TGT was issued to (MS-PAC 2.15).
pub const PAC_REQUESTOR: u32 = 18;
/// The extended KDC signature over the whole PAC, keyed with `krbtgt` (MS-PAC 2.8).
pub const PAC_FULL_CHECKSUM: u32 = 19;

/// AD-WIN2K-PAC, inside AD-IF-RELEVANT (RFC 4120 §7.5.4).
pub const AD_WIN2K_PAC: i32 = 128;
const AD_IF_RELEVANT: i32 = 1;

/// KRB5_KEYUSAGE_APP_DATA_CKSUM: every PAC signature's key usage.
const KU_PAC: u32 = 17;
/// KERB_CHECKSUM_HMAC_MD5 (RFC 4757), Windows' with RC4 keys.
const CKSUM_HMAC_MD5: i32 = -138;

/// MIT's limit on the buffer count.
const MAX_BUFFERS: u32 = 4096;

/// A PAC that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacError {
    /// The PAC or one of its buffers does not decode.
    #[error("malformed PAC: {0}")]
    Malformed(String),
    /// A signature did not verify (MIT's KRB5KRB_AP_ERR_MODIFIED).
    #[error("PAC signature does not verify: {0}")]
    BadSignature(String),
    /// The client info does not match the ticket (KRB5KRB_AP_WRONG_PRINC).
    #[error("PAC client info does not match the ticket: {0}")]
    WrongClient(String),
}

type Result<T> = std::result::Result<T, PacError>;

fn malformed<T>(m: impl Into<String>) -> Result<T> {
    Err(PacError::Malformed(m.into()))
}

/// A parsed PAC: the bytes and the buffer table, as MIT's
/// `krb5_pac_parse` checks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pac {
    data: Vec<u8>,
    /// (type, offset, size) for each PAC_INFO_BUFFER.
    buffers: Vec<(u32, usize, usize)>,
}

impl Pac {
    /// Parse a PACTYPE: version 0, 1 to 4096 buffers, each 8-aligned and
    /// inside the data.
    pub fn parse(data: &[u8]) -> Result<Pac> {
        let mut r = Le::new(data);
        let (count, version) = (r.u32()?, r.u32()?);
        if version != 0 {
            return malformed(format!("version {version}"));
        }
        if count == 0 || count > MAX_BUFFERS {
            return malformed(format!("{count} buffers"));
        }
        let header = 8 + 16 * count as usize;
        if data.len() < header {
            return malformed("shorter than its buffer table");
        }
        let mut buffers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (ty, size, offset) = (r.u32()?, r.u32()? as usize, r.u64()?);
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            if offset % 8 != 0 {
                return malformed(format!("buffer {ty} at unaligned offset {offset}"));
            }
            if offset < header || offset > data.len() || size > data.len() - offset {
                return malformed(format!("buffer {ty} lies outside the PAC"));
            }
            buffers.push((ty, offset, size));
        }
        Ok(Pac {
            data: data.to_vec(),
            buffers,
        })
    }

    /// The PAC as encoded.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The buffer types, in table order.
    pub fn buffer_types(&self) -> impl Iterator<Item = u32> + '_ {
        self.buffers.iter().map(|b| b.0)
    }

    /// The first buffer of type `ty`.
    pub fn buffer(&self, ty: u32) -> Option<&[u8]> {
        self.locate(ty).map(|(o, s)| &self.data[o..o + s])
    }

    fn locate(&self, ty: u32) -> Option<(usize, usize)> {
        self.buffers
            .iter()
            .find(|b| b.0 == ty)
            .map(|&(_, o, s)| (o, s))
    }

    /// PAC_LOGON_INFO: the user's identity and groups.
    pub fn logon_info(&self) -> Result<Option<LogonInfo>> {
        self.buffer(PAC_LOGON_INFO)
            .map(LogonInfo::decode)
            .transpose()
    }

    /// PAC_CLIENT_INFO: the client name and authentication time.
    pub fn client_info(&self) -> Result<Option<ClientInfo>> {
        self.buffer(PAC_CLIENT_INFO)
            .map(ClientInfo::decode)
            .transpose()
    }

    /// UPN_DNS_INFO: the user principal name, DNS domain and, extended,
    /// the SAM name and SID.
    pub fn upn_dns_info(&self) -> Result<Option<UpnDnsInfo>> {
        self.buffer(PAC_UPN_DNS_INFO)
            .map(UpnDnsInfo::decode)
            .transpose()
    }

    /// PAC_DELEGATION_INFO (S4U_DELEGATION_INFO): the S4U2Proxy target
    /// and the services the ticket came through.
    pub fn delegation_info(&self) -> Result<Option<DelegationInfo>> {
        self.buffer(PAC_DELEGATION_INFO)
            .map(DelegationInfo::decode)
            .transpose()
    }

    /// PAC_ATTRIBUTES_INFO flags: 1, the PAC was asked for; 2, it was
    /// given without being asked for.
    pub fn attributes(&self) -> Result<Option<u32>> {
        self.buffer(PAC_ATTRIBUTES_INFO)
            .map(|b| {
                let mut r = Le::new(b);
                let (_bits, flags) = (r.u32()?, r.u32()?);
                Ok(flags)
            })
            .transpose()
    }

    /// PAC_REQUESTOR: the SID of the client the TGT was issued to.
    pub fn requestor_sid(&self) -> Result<Option<Sid>> {
        self.buffer(PAC_REQUESTOR)
            .map(|b| Sid::from_bytes(b).map(|(s, _)| s))
            .transpose()
    }

    /// A signature buffer: (checksum type, checksum).
    pub fn signature(&self, ty: u32) -> Result<Option<(i32, &[u8])>> {
        let Some(b) = self.buffer(ty) else {
            return Ok(None);
        };
        if b.len() < 4 {
            return malformed(format!("signature buffer {ty} too short"));
        }
        let cksumtype = i32::from_le_bytes(b[..4].try_into().unwrap());
        // An RODCIdentifier may follow (MS-PAC 2.8): take the type's length.
        let len = checksum_len(cksumtype)
            .ok_or_else(|| PacError::Malformed(format!("checksum type {cksumtype}")))?;
        let sum = b
            .get(4..4 + len)
            .ok_or_else(|| PacError::Malformed(format!("signature buffer {ty} too short")))?;
        Ok(Some((cksumtype, sum)))
    }

    /// The PAC with the given signatures' values zeroed, as MIT's
    /// `zero_signature` makes the copy every PAC signature is over.
    fn zeroed(&self, types: &[u32]) -> Result<Vec<u8>> {
        let mut copy = self.data.clone();
        for &ty in types {
            let (o, s) = self
                .locate(ty)
                .ok_or_else(|| PacError::Malformed(format!("no signature buffer {ty}")))?;
            if s < 4 {
                return malformed(format!("signature buffer {ty} too short"));
            }
            copy[o + 4..o + s].fill(0);
        }
        Ok(copy)
    }

    /// The server signature (PAC_SERVER_CHECKSUM), with the key of the
    /// service the ticket is for: over the PAC with the server and KDC
    /// signatures zeroed.
    pub fn verify_server_signature(&self, key: &Key) -> Result<()> {
        let copy = self.zeroed(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM])?;
        self.verify(PAC_SERVER_CHECKSUM, key.enctype(), key.bytes(), &copy)
    }

    /// The KDC signature (PAC_PRIVSVR_CHECKSUM), with the `krbtgt` key:
    /// over the server signature's value.
    pub fn verify_kdc_signature(&self, krbtgt: &Key) -> Result<()> {
        let (_, server) = self
            .signature(PAC_SERVER_CHECKSUM)?
            .ok_or_else(|| PacError::Malformed("no server signature".into()))?;
        let server = server.to_vec();
        self.verify(
            PAC_PRIVSVR_CHECKSUM,
            krbtgt.enctype(),
            krbtgt.bytes(),
            &server,
        )
    }

    /// The full signature (PAC_FULL_CHECKSUM, 2022 and later), with the
    /// `krbtgt` key: over the PAC with the server, KDC and full signatures
    /// zeroed.
    pub fn verify_full_signature(&self, krbtgt: &Key) -> Result<()> {
        let copy = self.zeroed(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_FULL_CHECKSUM])?;
        self.verify(PAC_FULL_CHECKSUM, krbtgt.enctype(), krbtgt.bytes(), &copy)
    }

    /// Verify signature buffer `ty` over `data`: HMAC-MD5 with any key's
    /// octets, as MIT allows, or the simplified-profile checksum of the
    /// key's own enctype.
    fn verify(&self, ty: u32, enctype: i32, key: &[u8], data: &[u8]) -> Result<()> {
        let (cksumtype, sum) = self
            .signature(ty)?
            .ok_or_else(|| PacError::Malformed(format!("no signature buffer {ty}")))?;
        let ok = match cksumtype {
            CKSUM_HMAC_MD5 => crate::md5::hmac_md5_checksum(key, KU_PAC, data) == sum,
            15..=16 | 19..=20 => {
                let want = match cksumtype {
                    15 => 17,
                    16 => 18,
                    t => t,
                };
                if enctype != want {
                    return Err(PacError::BadSignature(format!(
                        "signature type {cksumtype} needs an enctype {want} key, not {enctype}"
                    )));
                }
                let k = Key::new(enctype, key.to_vec())
                    .map_err(|e| PacError::BadSignature(e.to_string()))?;
                k.verify_checksum(KU_PAC, data, sum)
                    .map_err(|e| PacError::BadSignature(e.to_string()))?
            }
            t => {
                return Err(PacError::BadSignature(format!(
                    "unkeyed or unsupported checksum type {t}"
                )));
            }
        };
        if ok {
            Ok(())
        } else {
            Err(PacError::BadSignature(format!("buffer {ty}")))
        }
    }

    /// MIT's `k5_pac_validate_client`: the client info names `client`
    /// (without its realm unless `with_realm`, as MIT unparses it for
    /// display) at `authtime` (Unix seconds).
    pub fn verify_client(
        &self,
        authtime: i64,
        client: &crate::Principal,
        with_realm: bool,
    ) -> Result<()> {
        let info = self
            .client_info()?
            .ok_or_else(|| PacError::Malformed("no client info".into()))?;
        let mut name = client.components.join("/");
        if with_realm {
            name = format!("{name}@{}", client.realm);
        }
        if info.authtime.unix_secs() != Some(authtime) || info.name != name {
            return Err(PacError::WrongClient(format!(
                "{} at {:?}, not {name} at {authtime}",
                info.name,
                info.authtime.unix_secs()
            )));
        }
        Ok(())
    }
}

/// The checksum length for a PAC signature type (MIT's
/// `krb5_c_checksum_length`).
fn checksum_len(cksumtype: i32) -> Option<usize> {
    match cksumtype {
        CKSUM_HMAC_MD5 => Some(16),
        15 | 16 => Some(12),
        19 => Some(16),
        20 => Some(24),
        _ => None,
    }
}

/// The PAC in a ticket's AuthorizationData (DER), as MIT finds it: the
/// first AD-WIN2K-PAC inside an AD-IF-RELEVANT.
pub fn find_pac(authorization_data: &[u8]) -> Result<Option<&[u8]>> {
    let bad = |e: der::DerError| PacError::Malformed(format!("authorization data: {}", e.0));
    let mut outer = Reader::new(authorization_data).seq().map_err(bad)?;
    while !outer.is_empty() {
        let f = Fields::parse(
            "AuthorizationData",
            outer.expect(der::SEQUENCE).map_err(bad)?,
        )
        .map_err(bad)?;
        if f.get(0).and_then(|mut r| r.i32()).map_err(bad)? != AD_IF_RELEVANT {
            continue;
        }
        let inner = f.get(1).and_then(|mut r| r.octets()).map_err(bad)?;
        let mut list = Reader::new(inner).seq().map_err(bad)?;
        while !list.is_empty() {
            let e = Fields::parse(
                "AuthorizationData",
                list.expect(der::SEQUENCE).map_err(bad)?,
            )
            .map_err(bad)?;
            if e.get(0).and_then(|mut r| r.i32()).map_err(bad)? == AD_WIN2K_PAC {
                return Ok(Some(e.get(1).and_then(|mut r| r.octets()).map_err(bad)?));
            }
        }
    }
    Ok(None)
}

/// The ticket signature (PAC_TICKET_CHECKSUM, 2021 and later), with the
/// `krbtgt` key, as MIT's `krb5_kdc_verify_ticket` checks it: over the
/// EncTicketPart (DER, decrypted) re-encoded with the PAC replaced by a
/// single zero octet. A KDC's check, not a service's.
pub fn verify_ticket_signature(enc_ticket_part: &[u8], krbtgt: &Key) -> Result<()> {
    let bad = |e: der::DerError| PacError::Malformed(format!("EncTicketPart: {}", e.0));
    let f = Fields::parse_tagged("EncTicketPart", der::app(3), enc_ticket_part).map_err(bad)?;
    let ad = f.raw(10).map_err(bad)?;
    let pac = Pac::parse(find_pac(ad)?.ok_or_else(|| PacError::Malformed("no PAC".into()))?)?;
    // Re-encode, element by element: other fields keep their bytes.
    let mut outer = Reader::new(ad).seq().map_err(bad)?;
    let mut entries = Vec::new();
    let mut replaced = false;
    while !outer.is_empty() {
        let raw = outer.expect(der::SEQUENCE).map_err(bad)?;
        let e = Fields::parse("AuthorizationData", raw).map_err(bad)?;
        let ty = e.get(0).and_then(|mut r| r.i32()).map_err(bad)?;
        if ty != AD_IF_RELEVANT || replaced {
            entries.push(der::tlv(der::SEQUENCE, raw));
            continue;
        }
        let inner = e.get(1).and_then(|mut r| r.octets()).map_err(bad)?;
        let mut list = Reader::new(inner).seq().map_err(bad)?;
        let mut items = Vec::new();
        while !list.is_empty() {
            let raw = list.expect(der::SEQUENCE).map_err(bad)?;
            let it = Fields::parse("AuthorizationData", raw).map_err(bad)?;
            if !replaced && it.get(0).and_then(|mut r| r.i32()).map_err(bad)? == AD_WIN2K_PAC {
                replaced = true;
                items.push(der::seq(&[
                    der::field(0, der::int(AD_WIN2K_PAC.into())),
                    der::field(1, der::octets(&[0])),
                ]));
            } else {
                items.push(der::tlv(der::SEQUENCE, raw));
            }
        }
        entries.push(der::seq(&[
            der::field(0, der::int(AD_IF_RELEVANT.into())),
            der::field(1, der::octets(&der::seq(&items))),
        ]));
    }
    let mut fields = Vec::new();
    for n in 0..=10u8 {
        if n == 10 {
            fields.push(der::field(10, der::seq(&entries)));
        } else if let Some(raw) = f.opt(n).map(|_| f.raw(n).unwrap()) {
            fields.push(der::tlv(der::ctx(n), raw));
        }
    }
    let recoded = der::cons(der::app(3), &[der::seq(&fields)]);
    pac.verify(
        PAC_TICKET_CHECKSUM,
        krbtgt.enctype(),
        krbtgt.bytes(),
        &recoded,
    )
}

/// MIT's `krb5_kdc_verify_ticket`: decrypt `ticket` (a Ticket, DER) with
/// the service's key, and check every signature on its PAC: the server's
/// with that key, the KDC's with the `krbtgt` key, and for a service
/// ticket (not a TGT, nor `kadmin/changepw`, MS-PAC 2.8.3) the ticket
/// and full signatures too. The PAC, or `None` for a ticket without one.
/// Like MIT 1.21 and later, a service ticket's PAC must carry the full
/// signature (the CVE-2022-37967 fix); KDCs before it (MIT 1.20, Windows
/// before November 2022) don't add one, and their tickets are refused.
/// What a KDC (or a test of one) checks; a service has no `krbtgt` key.
pub fn verify_ticket(ticket: &[u8], service_key: &Key, krbtgt: &Key) -> Result<Option<Pac>> {
    let bad = |e: der::DerError| PacError::Malformed(format!("Ticket: {}", e.0));
    let t = Fields::parse_tagged("Ticket", der::app(1), ticket).map_err(bad)?;
    let sname = crate::Principal::decode_name(t.get(2).map_err(bad)?, String::new())
        .map_err(|e| PacError::Malformed(e.to_string()))?;
    let (_, cipher) = crate::client::decode_encrypted_data(t.get(3).map_err(bad)?)
        .map_err(|e| PacError::Malformed(e.to_string()))?;
    let enc = service_key
        .decrypt(2, &cipher)
        .map_err(|e| PacError::BadSignature(format!("cannot decrypt the ticket: {e}")))?;
    let f = Fields::parse_tagged("EncTicketPart", der::app(3), &enc).map_err(bad)?;
    let Some(ad) = f.opt(10).map(|_| f.raw(10).unwrap()) else {
        return Ok(None);
    };
    let Some(raw) = find_pac(ad)? else {
        return Ok(None);
    };
    let pac = Pac::parse(raw)?;
    let service_ticket = !(sname.components.len() == 2 && sname.components[0] == "krbtgt"
        || sname.components == ["kadmin", "changepw"]);
    if service_ticket {
        verify_ticket_signature(&enc, krbtgt)?;
        pac.verify_full_signature(krbtgt)?;
    }
    pac.verify_server_signature(service_key)?;
    pac.verify_kdc_signature(krbtgt)?;
    Ok(Some(pac))
}

/// A Windows FILETIME: 100-nanosecond intervals since 1601.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTime(pub u64);

impl FileTime {
    /// Unix seconds, or `None` for "never" (0, or the maximum, as Windows
    /// writes it).
    pub fn unix_secs(self) -> Option<i64> {
        match self.0 {
            0 | 0x7FFF_FFFF_FFFF_FFFF | u64::MAX => None,
            t => Some((t / 10_000_000) as i64 - 11_644_473_600),
        }
    }
}

/// A security identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    /// The SID revision, 1.
    pub revision: u8,
    /// The 48-bit identifier authority.
    pub authority: u64,
    /// The sub-authorities; in a domain account's SID the last is its RID.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// The binary form (MS-DTYP 2.4.22), and the octets it took.
    pub fn from_bytes(b: &[u8]) -> Result<(Sid, usize)> {
        if b.len() < 8 {
            return malformed("SID too short");
        }
        let count = b[1] as usize;
        let len = 8 + 4 * count;
        if b.len() < len {
            return malformed("SID shorter than its sub-authority count");
        }
        let authority = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64);
        let subs = b[8..len]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok((
            Sid {
                revision: b[0],
                authority,
                sub_authorities: subs,
            },
            len,
        ))
    }

    /// This SID with `rid` appended: a domain SID and a relative ID.
    pub fn with_rid(&self, rid: u32) -> Sid {
        let mut s = self.clone();
        s.sub_authorities.push(rid);
        s
    }
}

impl fmt::Display for Sid {
    /// `S-1-5-21-…`, as Windows writes it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-", self.revision)?;
        if self.authority >> 32 == 0 {
            write!(f, "{}", self.authority)?;
        } else {
            write!(f, "0x{:012X}", self.authority)?;
        }
        for s in &self.sub_authorities {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

/// PAC_CLIENT_INFO.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientInfo {
    /// `ClientId`: the ticket's authtime.
    pub authtime: FileTime,
    /// The client's principal name, without the realm.
    pub name: String,
}

impl ClientInfo {
    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Le::new(b);
        let (authtime, len) = (FileTime(r.u64()?), r.u16()? as usize);
        if len % 2 != 0 {
            return malformed("client name length is odd");
        }
        Ok(ClientInfo {
            authtime,
            name: utf16(r.bytes(len)?)?,
        })
    }
}

/// UPN_DNS_INFO (MS-PAC 2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpnDnsInfo {
    /// The user principal name.
    pub upn: String,
    /// The DNS name of the user's domain.
    pub dns_domain: String,
    /// Flag U (1): the account has no UPN; this one was made up from the
    /// SAM name and domain.
    pub upn_constructed: bool,
    /// With flag S (2): the SAM account name and the user's SID.
    pub sam_name: Option<String>,
    /// The user's SID, with flag S.
    pub sid: Option<Sid>,
}

impl UpnDnsInfo {
    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Le::new(b);
        let field = |len: u16, off: u16| -> Result<&[u8]> {
            b.get(off as usize..off as usize + len as usize)
                .ok_or_else(|| PacError::Malformed("UPN_DNS_INFO field overruns".into()))
        };
        let (ul, uo, dl, dof, flags) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?, r.u32()?);
        let (mut sam_name, mut sid) = (None, None);
        if flags & 2 != 0 {
            let (sl, so, il, io) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
            sam_name = Some(utf16(field(sl, so)?)?);
            sid = Some(Sid::from_bytes(field(il, io)?)?.0);
        }
        Ok(UpnDnsInfo {
            upn: utf16(field(ul, uo)?)?,
            dns_domain: utf16(field(dl, dof)?)?,
            upn_constructed: flags & 1 != 0,
            sam_name,
            sid,
        })
    }
}

/// A group membership: a relative ID and its SE_GROUP_* attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMembership {
    /// `RelativeId`: the group's RID in its domain.
    pub rid: u32,
    /// `Attributes`: SE_GROUP_* flags.
    pub attributes: u32,
}

/// PAC_LOGON_INFO: `KERB_VALIDATION_INFO` (MS-PAC 2.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LogonInfo {
    /// `LogonTime`: when the user logged on (FILETIME).
    pub logon_time: FileTime,
    /// `LogoffTime`: when the logon session expires; "never" if none.
    pub logoff_time: FileTime,
    /// `KickOffTime`: when the server should force a logoff; "never" if none.
    pub kickoff_time: FileTime,
    /// `PasswordLastSet`: when the password last changed.
    pub password_last_set: FileTime,
    /// `PasswordCanChange`: the earliest time the password may change.
    pub password_can_change: FileTime,
    /// `PasswordMustChange`: when the password expires.
    pub password_must_change: FileTime,
    /// `EffectiveName`: the SAM account name.
    pub effective_name: String,
    /// `FullName`: the user's display name.
    pub full_name: String,
    /// `LogonScript`: the logon script path.
    pub logon_script: String,
    /// `ProfilePath`: the roaming profile path.
    pub profile_path: String,
    /// `HomeDirectory`: the home directory path.
    pub home_directory: String,
    /// `HomeDirectoryDrive`: the drive letter the home directory maps to.
    pub home_directory_drive: String,
    /// `LogonCount`: successful logons, as the DC counts them.
    pub logon_count: u16,
    /// `BadPasswordCount`: failed logons since the last success.
    pub bad_password_count: u16,
    /// `UserId`: the user's RID in the logon domain.
    pub user_id: u32,
    /// `PrimaryGroupId`: the primary group's RID in the logon domain.
    pub primary_group_id: u32,
    /// `GroupIds`: the logon domain's groups the user is in.
    pub group_ids: Vec<GroupMembership>,
    /// `UserFlags`: LOGON_* flags (e.g. LOGON_EXTRA_SIDS, LOGON_RESOURCE_GROUPS).
    pub user_flags: u32,
    /// `UserSessionKey`: zero in a Kerberos PAC.
    pub user_session_key: [u8; 16],
    /// `LogonServer`: the NetBIOS name of the DC that authenticated the user.
    pub logon_server: String,
    /// `LogonDomainName`: the NetBIOS name of the user's domain.
    pub logon_domain_name: String,
    /// `LogonDomainId`: the domain SID that `user_id` and `group_ids` are relative to.
    pub logon_domain_id: Option<Sid>,
    /// `UserAccountControl`: USER_* account flags (MS-SAMR 2.2.1.12).
    pub user_account_control: u32,
    /// `SubAuthStatus`: the subauthentication package's status; zero if none.
    pub sub_auth_status: u32,
    /// `LastSuccessfulILogon`: the last interactive logon, if the DC records it.
    pub last_successful_i_logon: FileTime,
    /// `LastFailedILogon`: the last failed interactive logon, if the DC records it.
    pub last_failed_i_logon: FileTime,
    /// `FailedILogonCount`: failed interactive logons since the last success.
    pub failed_i_logon_count: u32,
    /// Other SIDs (universal groups from other domains, well-known SIDs),
    /// with their attributes.
    pub extra_sids: Vec<(Sid, u32)>,
    /// `ResourceGroupDomainSid`: the domain SID that `resource_group_ids` are relative to.
    pub resource_group_domain_sid: Option<Sid>,
    /// `ResourceGroupIds`: domain-local groups of the resource domain.
    pub resource_group_ids: Vec<GroupMembership>,
}

impl LogonInfo {
    /// The user's SID: the logon domain's and the user's relative ID.
    pub fn user_sid(&self) -> Option<Sid> {
        self.logon_domain_id
            .as_ref()
            .map(|d| d.with_rid(self.user_id))
    }

    /// Every group SID the PAC grants: domain groups, extra SIDs, and
    /// resource groups, in that order.
    pub fn group_sids(&self) -> Vec<Sid> {
        let mut out = Vec::new();
        if let Some(d) = &self.logon_domain_id {
            out.extend(self.group_ids.iter().map(|g| d.with_rid(g.rid)));
        }
        out.extend(self.extra_sids.iter().map(|(s, _)| s.clone()));
        if let Some(d) = &self.resource_group_domain_sid {
            out.extend(self.resource_group_ids.iter().map(|g| d.with_rid(g.rid)));
        }
        out
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Ndr::new(b)?;
        if r.ptr()? == 0 {
            return malformed("KERB_VALIDATION_INFO pointer is null");
        }
        let mut v = LogonInfo {
            logon_time: r.filetime()?,
            logoff_time: r.filetime()?,
            kickoff_time: r.filetime()?,
            password_last_set: r.filetime()?,
            password_can_change: r.filetime()?,
            password_must_change: r.filetime()?,
            ..Default::default()
        };
        // Six RPC_UNICODE_STRINGs: their buffers come after the struct.
        let names: Vec<u32> = (0..6).map(|_| r.unicode_string()).collect::<Result<_>>()?;
        v.logon_count = r.u16()?;
        v.bad_password_count = r.u16()?;
        v.user_id = r.u32()?;
        v.primary_group_id = r.u32()?;
        let group_count = r.u32()?;
        let groups_ptr = r.ptr()?;
        v.user_flags = r.u32()?;
        v.user_session_key = r.bytes(16)?.try_into().unwrap();
        let server = r.unicode_string()?;
        let domain = r.unicode_string()?;
        let domain_id_ptr = r.ptr()?;
        r.u32()?;
        r.u32()?; // Reserved1
        v.user_account_control = r.u32()?;
        v.sub_auth_status = r.u32()?;
        v.last_successful_i_logon = r.filetime()?;
        v.last_failed_i_logon = r.filetime()?;
        v.failed_i_logon_count = r.u32()?;
        r.u32()?; // Reserved3
        let sid_count = r.u32()?;
        let extra_ptr = r.ptr()?;
        let resource_domain_ptr = r.ptr()?;
        let resource_count = r.u32()?;
        let resource_ptr = r.ptr()?;

        // The deferred referents, in the order of their pointers.
        let mut strings = Vec::new();
        for p in names {
            strings.push(r.deferred_string(p)?);
        }
        [
            v.effective_name,
            v.full_name,
            v.logon_script,
            v.profile_path,
            v.home_directory,
            v.home_directory_drive,
        ] = strings.try_into().unwrap();
        v.group_ids = r.deferred_groups(groups_ptr, group_count)?;
        v.logon_server = r.deferred_string(server)?;
        v.logon_domain_name = r.deferred_string(domain)?;
        v.logon_domain_id = r.deferred_sid(domain_id_ptr)?;
        if extra_ptr != 0 {
            let n = r.conformance(sid_count)?;
            let entries: Vec<(u32, u32)> = (0..n)
                .map(|_| Ok((r.ptr()?, r.u32()?)))
                .collect::<Result<_>>()?;
            for (p, attrs) in entries {
                if let Some(s) = r.deferred_sid(p)? {
                    v.extra_sids.push((s, attrs));
                }
            }
        }
        v.resource_group_domain_sid = r.deferred_sid(resource_domain_ptr)?;
        v.resource_group_ids = r.deferred_groups(resource_ptr, resource_count)?;
        Ok(v)
    }
}

/// PAC_DELEGATION_INFO: `S4U_DELEGATION_INFO` (MS-PAC 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DelegationInfo {
    /// The service the S4U2Proxy ticket is for.
    pub proxy_target: String,
    /// The services the ticket was obtained by, in order.
    pub transited_services: Vec<String>,
}

impl DelegationInfo {
    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Ndr::new(b)?;
        if r.ptr()? == 0 {
            return malformed("S4U_DELEGATION_INFO pointer is null");
        }
        let target = r.unicode_string()?;
        let count = r.u32()?;
        let list_ptr = r.ptr()?;
        let proxy_target = r.deferred_string(target)?;
        let mut transited_services = Vec::new();
        if list_ptr != 0 {
            let n = r.conformance(count)?;
            let ptrs: Vec<u32> = (0..n).map(|_| r.unicode_string()).collect::<Result<_>>()?;
            for p in ptrs {
                transited_services.push(r.deferred_string(p)?);
            }
        }
        Ok(DelegationInfo {
            proxy_target,
            transited_services,
        })
    }
}

fn utf16(b: &[u8]) -> Result<String> {
    if b.len() % 2 != 0 {
        return malformed("UTF-16 string of odd length");
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| PacError::Malformed("bad UTF-16".into()))
}

/// A little-endian cursor.
struct Le<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Le<'a> {
    fn new(b: &'a [u8]) -> Self {
        Le { b, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos.saturating_add(n))
            .ok_or_else(|| PacError::Malformed("truncated".into()))?;
        self.pos += n;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
}

/// An NDR (MS-RPCE 2.2.6) type-serialization-1 reader, little-endian:
/// every primitive aligned to its size, from the start of the data.
struct Ndr<'a> {
    r: Le<'a>,
}

impl<'a> Ndr<'a> {
    /// Check the 16-octet common and private headers.
    fn new(b: &'a [u8]) -> Result<Self> {
        let mut r = Le::new(b);
        let (version, endian, header_len) = (r.bytes(1)?[0], r.bytes(1)?[0], r.u16()?);
        if version != 1 || endian != 0x10 || header_len != 8 {
            return malformed("not a little-endian NDR type serialization");
        }
        r.u32()?; // filler
        let len = r.u32()? as usize;
        r.u32()?; // filler
        if len > b.len() - 16 {
            return malformed("NDR object longer than its buffer");
        }
        Ok(Ndr { r })
    }

    fn align(&mut self, n: usize) -> Result<()> {
        let pad = (n - self.r.pos % n) % n;
        self.r.bytes(pad).map(|_| ())
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.r.bytes(n)
    }

    fn u16(&mut self) -> Result<u16> {
        self.align(2)?;
        self.r.u16()
    }

    fn u32(&mut self) -> Result<u32> {
        self.align(4)?;
        self.r.u32()
    }

    /// A unique or full pointer's referent ID (0 for null).
    fn ptr(&mut self) -> Result<u32> {
        self.u32()
    }

    /// FILETIME is two DWORDs: aligned to 4, not 8.
    fn filetime(&mut self) -> Result<FileTime> {
        let lo = self.u32()? as u64;
        Ok(FileTime(lo | (self.u32()? as u64) << 32))
    }

    /// RPC_UNICODE_STRING's inline part: Length, MaximumLength, Buffer
    /// pointer. Returns the pointer (the length comes with the referent).
    fn unicode_string(&mut self) -> Result<u32> {
        self.u16()?;
        self.u16()?;
        self.ptr()
    }

    /// A conformant array's MaximumCount, which must be the count the
    /// struct gave.
    fn conformance(&mut self, count: u32) -> Result<u32> {
        let n = self.u32()?;
        if n != count {
            return malformed(format!("array of {n}, but the count says {count}"));
        }
        // No more elements than octets left: no huge allocations.
        if n as usize > self.r.b.len() {
            return malformed("array longer than the buffer");
        }
        Ok(n)
    }

    /// The conformant varying array of WCHAR an RPC_UNICODE_STRING points
    /// to.
    fn deferred_string(&mut self, ptr: u32) -> Result<String> {
        if ptr == 0 {
            return Ok(String::new());
        }
        let _max = self.u32()?;
        let offset = self.u32()?;
        let actual = self.u32()? as usize;
        if offset != 0 {
            return malformed("string with a nonzero offset");
        }
        let s = utf16(self.bytes(actual.saturating_mul(2))?)?;
        Ok(s)
    }

    /// A conformant array of GROUP_MEMBERSHIP.
    fn deferred_groups(&mut self, ptr: u32, count: u32) -> Result<Vec<GroupMembership>> {
        if ptr == 0 {
            return Ok(Vec::new());
        }
        let n = self.conformance(count)?;
        (0..n)
            .map(|_| {
                Ok(GroupMembership {
                    rid: self.u32()?,
                    attributes: self.u32()?,
                })
            })
            .collect()
    }

    /// An RPC_SID: conformance (the sub-authority count), then the SID.
    fn deferred_sid(&mut self, ptr: u32) -> Result<Option<Sid>> {
        if ptr == 0 {
            return Ok(None);
        }
        let n = self.u32()? as usize;
        let head = self.bytes(8)?;
        if head[1] as usize != n {
            return malformed("SID sub-authority count disagrees with its conformance");
        }
        let mut raw = head.to_vec();
        raw.extend_from_slice(self.bytes(4 * n)?);
        Ok(Some(Sid::from_bytes(&raw)?.0))
    }
}

#[cfg(test)]
mod tests;
