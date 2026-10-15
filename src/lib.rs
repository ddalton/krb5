//! Pure-Rust Kerberos 5: GSS-API acceptor and initiator, plus a KDC client.
//!
//! No dependency on MIT krb5, Heimdal or glibc.
//!
//! **Server side**
//! * [`Keytab`] — load service keys from an MIT-format keytab.
//! * [`KerberosContext::accept_token`] — validate an AP-REQ (ticket,
//!   authenticator, clock skew, validity window) and build the AP-REP
//!   when mutual authentication was requested; bare AP-REQs too
//!   ([`KerberosContext::accept_ap_req`]), and user-to-user tickets,
//!   accepted with a TGT ([`KerberosContext::accept_token_u2u`]).
//! * [`rcache`] — replay detection, on by default: in memory and
//!   sharded, or any shared store.
//!
//! **Client side**
//! * [`KdcClient`] — the AS exchange (`kinit`, with a password or a
//!   keytab, including PA-ENC-TIMESTAMP pre-authentication) and the TGS
//!   exchange (service tickets, across realms by referral and
//!   `[capaths]`), over UDP and TCP as MIT chooses between them; ticket
//!   renewal and postdated tickets (`kinit -R`, `-s`, `-v`); one-time
//!   passwords ([`KdcClient::login_with_otp`], RFC 6560); S4U2Self and
//!   S4U2Proxy ([`KdcClient::s4u2self`], [`KdcClient::s4u2proxy`]):
//!   protocol transition and constrained delegation, traditional and
//!   resource-based; user-to-user tickets ([`KdcClient::user_to_user`],
//!   `kvno --u2u`).
//! * `pkinit` (with the `pkinit` feature) — PKINIT: login with an X.509
//!   certificate (`kinit -X`), anonymous PKINIT (`kinit -n`), and FAST
//!   armor from it (`auto_fast_armor`), in pure Rust.
//! * [`kadmin::AdminClient`] — `kadmin` against MIT's `kadmind`:
//!   principals (`addprinc`, `getprinc`, `modprinc`, `cpw`, `ktadd`, ...),
//!   policies and string attributes, over RPCSEC_GSS with privacy.
//! * [`kpasswd`] — password changes (`kpasswd`) and RFC 3244 set-password,
//!   to `kadmind` or Active Directory.
//! * [`CCache`] / [`CacheName`] — MIT `FILE:`, `DIR:` and `KCM:`
//!   credential caches, read and written, for tickets shared with `kinit`
//!   and `klist`; [`KdcClient::service_ticket_cached`] is `kvno`.
//! * [`Krb5Conf`] — `krb5.conf`, for the default realm, a realm's KDCs
//!   ([`KdcClient::discover`]) and `[domain_realm]`; [`dns`] finds KDCs
//!   from URI and SRV records when `krb5.conf` lists none.
//! * [`InitiatorContext`] — `gss_init_sec_context`: the AP-REQ token and
//!   verification of the acceptor's AP-REP.
//!
//! **Authorization**: [`pac`] — the MS-PAC in tickets from Active
//! Directory and MIT: the client's SIDs and groups, UPN, delegation path,
//! and its signatures; the acceptor keeps a ticket's PAC once its server
//! signature and client info verify.
//!
//! **Both**: [`token::PerMessageTokens`] — RFC 4121 §4.2 Wrap and MIC;
//! [`spnego`] — RFC 4178 SPNEGO, initiator and acceptor (HTTP
//! `Negotiate`, SMB, Windows); [`ChannelBindings`] — RFC 4121 channel
//! bindings, with the TLS ones (RFC 5929, RFC 9266).
//!
//! Supported enctypes are the four AES ones: 17/18
//! (`aes{128,256}-cts-hmac-sha1-96`, RFC 3962) and 19/20
//! (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`, RFC 8009).
//! Not implemented: a KDC, KEYRING and API credential caches, and
//! macOS's Mach-based KCM.
//!
//! # Evidence
//!
//! Every crypto primitive is pinned to the published RFC test vectors.
//! The acceptor is tested against tickets and tokens recorded from a live
//! MIT KDC and MIT `libgssapi` (`testdata/`). The client is tested live
//! against an MIT KDC (`tests/kdc.rs`), and its GSS tokens against MIT's
//! own acceptor (`scripts/mit-acceptor.py`), for all four enctypes. A
//! self-round-trip test is not evidence for a wire format: if it
//! round-trips but disagrees with the RFC, it is a private cipher no other
//! implementation speaks.
//!
//! # Acceptor
//!
//! ```no_run
//! use krb5::{Keytab, KerberosContext};
//!
//! # fn main() -> krb5::Result<()> {
//! # let init_token: Vec<u8> = vec![];
//! let keytab = Keytab::load("/etc/krb5.keytab")?;
//! let (ctx, ap_rep) = KerberosContext::accept_token(&keytab, &init_token)?;
//! println!("authenticated {}", ctx.client_principal);
//! // Send `ap_rep` back to the client (empty unless mutual auth was asked for).
//! let tokens = ctx.per_message_tokens()?;
//! # let _ = (ap_rep, tokens);
//! # Ok(())
//! # }
//! ```
//!
//! # Initiator
//!
//! ```no_run
//! use krb5::initiator::{GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
//! use krb5::{InitiatorContext, KdcClient, Principal};
//!
//! # fn send(_: &[u8]) -> Vec<u8> { vec![] }
//! # fn main() -> Result<(), krb5::ClientError> {
//! let kdc = KdcClient::new("EXAMPLE.COM", ["kdc.example.com"]);
//! let tgt = kdc.login_with_password(&Principal::parse("alice@EXAMPLE.COM")?, "secret")?;
//! let creds = kdc.service_ticket(&tgt, &Principal::parse("nfs/server.example.com@EXAMPLE.COM")?)?;
//!
//! let (mut ctx, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)?;
//! let ap_rep = send(&token);          // to the server, which replies with its AP-REP
//! ctx.step(&ap_rep)?;
//! let tokens = ctx.per_message_tokens()?;
//! let mic = tokens.emit_mic(ctx.send_seq(), b"message")
//!     .map_err(|e| krb5::ClientError::Protocol(e.to_string()))?;
//! # let _ = mic;
//! # Ok(())
//! # }
//! ```

pub mod acceptor;
pub mod bindings; // GSS-API channel bindings (RFC 4121 §4.1.1.2, RFC 5929)
pub mod ccache; // FILE: and DIR: credential caches, MIT format
pub mod client;
pub mod config; // krb5.conf: default realm, KDCs, [domain_realm]
mod der;
pub mod dns; // KDC discovery: URI and SRV records, stub resolver
pub mod initiator;
pub mod kadmin; // kadmind's kadm5 RPC protocol: what kadmin does
pub mod kdf; // RFC 3961 §5.1 DR/DK, RFC 3962 §4, RFC 8009 §3
pub mod key;
pub mod kpasswd; // password changes over the kpasswd protocol (RFC 3244)
mod md5; // RFC 1321 and HMAC-MD5: channel bindings, PAC signatures, MS-SFU
pub mod nfold; // RFC 3961 §5.1 n-fold
pub mod pac; // MS-PAC: the authorization data Windows and MIT put in tickets
#[cfg(feature = "pkinit")]
pub mod pkinit; // RFC 4556 PKINIT, RFC 8062 anonymous PKINIT
pub mod profile; // RFC 3961 §5.3 simplified profile (confounder + HMAC)
pub mod rcache; // replay detection for AP-REQs (RFC 4120 §3.2.3)
pub mod spnego; // RFC 4178 SPNEGO, for HTTP Negotiate, SMB and Windows
pub mod token; // RFC 4121 §4.2 per-message Wrap and MIC tokens

#[cfg(test)]
mod interop; // MIT krb5 interop fixtures — the gate vectors cannot close
#[cfg(test)]
mod mit_vectors; // MIT krb5's crypto_tests known answers, enctypes 17-20

pub use acceptor::{
    DEFAULT_CLOCK_SKEW_SECS, EncType, KerberosContext, KerberosError, Keytab, Result, ServiceKey,
};
pub use bindings::ChannelBindings;
pub use ccache::{CCache, CacheError, CacheName};
pub use client::{ClientError, Credentials, KdcClient, Principal};
pub use config::{ConfigError, Krb5Conf};
pub use initiator::InitiatorContext;
pub use key::Key;
