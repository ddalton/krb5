//! Pure-Rust Kerberos 5: GSS-API acceptor and initiator, plus a KDC client.
//!
//! No dependency on MIT krb5, Heimdal or glibc.
//!
//! **Server side**
//! * [`Keytab`] — load service keys from an MIT-format keytab.
//! * [`KerberosContext::accept_token`] — validate an AP-REQ (ticket,
//!   authenticator, clock skew, validity window) and build the AP-REP
//!   when mutual authentication was requested.
//!
//! **Client side**
//! * [`KdcClient`] — the AS exchange (`kinit`, with a password or a
//!   keytab, including PA-ENC-TIMESTAMP pre-authentication) and the TGS
//!   exchange (service tickets, across realms by referral and
//!   `[capaths]`), over UDP and TCP as MIT chooses between them.
//! * [`CCache`] / [`CacheName`] — MIT `FILE:`, `DIR:` and `KCM:`
//!   credential caches, read and written, for tickets shared with `kinit`
//!   and `klist`; [`KdcClient::service_ticket_cached`] is `kvno`.
//! * [`Krb5Conf`] — `krb5.conf`, for the default realm, a realm's KDCs
//!   ([`KdcClient::discover`]) and `[domain_realm]`; [`dns`] finds KDCs
//!   from URI and SRV records when `krb5.conf` lists none.
//! * [`InitiatorContext`] — `gss_init_sec_context`: the AP-REQ token and
//!   verification of the acceptor's AP-REP.
//!
//! **Both**: [`token::PerMessageTokens`] — RFC 4121 §4.2 Wrap and MIC.
//!
//! Supported enctypes are the four AES ones: 17/18
//! (`aes{128,256}-cts-hmac-sha1-96`, RFC 3962) and 19/20
//! (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`, RFC 8009).
//! Not implemented: a KDC, PKINIT, KEYRING and API
//! credential caches, and macOS's Mach-based KCM.
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
pub mod ccache; // FILE: and DIR: credential caches, MIT format
pub mod client;
pub mod config; // krb5.conf: default realm, KDCs, [domain_realm]
mod der;
pub mod dns; // KDC discovery: URI and SRV records, stub resolver
pub mod initiator;
pub mod kdf; // RFC 3961 §5.1 DR/DK, RFC 3962 §4, RFC 8009 §3
pub mod key;
pub mod nfold; // RFC 3961 §5.1 n-fold
pub mod profile; // RFC 3961 §5.3 simplified profile (confounder + HMAC)
pub mod token; // RFC 4121 §4.2 per-message Wrap and MIC tokens

#[cfg(test)]
mod interop; // MIT krb5 interop fixtures — the gate vectors cannot close
#[cfg(test)]
mod mit_vectors; // MIT krb5's crypto_tests known answers, enctypes 17-20

pub use acceptor::{
    DEFAULT_CLOCK_SKEW_SECS, EncType, KerberosContext, KerberosError, Keytab, Result, ServiceKey,
};
pub use ccache::{CCache, CacheError, CacheName};
pub use client::{ClientError, Credentials, KdcClient, Principal};
pub use config::{ConfigError, Krb5Conf};
pub use initiator::InitiatorContext;
pub use key::Key;
