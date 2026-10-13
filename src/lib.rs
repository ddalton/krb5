//! Pure-Rust Kerberos 5, acceptor side.
//!
//! This crate implements what a server needs to authenticate Kerberos
//! clients through GSS-API (for example NFS over RPCSEC_GSS), with no
//! dependency on MIT krb5, Heimdal or glibc:
//!
//! * [`Keytab`] — load service keys from an MIT-format keytab.
//! * [`KerberosContext::accept_token`] — validate an AP-REQ (ticket,
//!   authenticator, clock skew, validity window) and build the AP-REP
//!   when mutual authentication was requested.
//! * [`token::PerMessageTokens`] — RFC 4121 §4.2 Wrap and MIC tokens for
//!   an established context.
//!
//! Supported enctypes are the four AES ones: 17/18
//! (`aes{128,256}-cts-hmac-sha1-96`, RFC 3962) and 19/20
//! (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`, RFC 8009).
//! There is no KDC and no initiator.
//!
//! # Evidence
//!
//! Every crypto primitive is pinned to the published RFC test vectors,
//! and the acceptor is tested against tickets and tokens recorded from a
//! live MIT KDC and MIT `libgssapi` (see `testdata/`). A self-round-trip
//! test is not evidence for a wire format: if it round-trips but
//! disagrees with the RFC, it is a private cipher no other
//! implementation speaks.
//!
//! # Example
//!
//! ```no_run
//! use krb5::{Keytab, KerberosContext};
//!
//! # fn main() -> krb5::Result<()> {
//! # let init_token: Vec<u8> = vec![];
//! let keytab = Keytab::load("/etc/krb5.keytab")?;
//! let (ctx, ap_rep) = KerberosContext::accept_token(&keytab, &init_token)?;
//! println!("authenticated {}@{}", ctx.client_principal, ctx.client_realm);
//! // Send `ap_rep` back to the client (empty unless mutual auth was asked for).
//! let tokens = ctx.per_message_tokens()?;
//! # let _ = (ap_rep, tokens);
//! # Ok(())
//! # }
//! ```

pub mod acceptor;
pub mod kdf;     // RFC 3961 §5.1 DR/DK, RFC 3962 §4, RFC 8009 §3
pub mod nfold;   // RFC 3961 §5.1 n-fold
pub mod profile; // RFC 3961 §5.3 simplified profile (confounder + HMAC)
pub mod token;   // RFC 4121 §4.2 per-message Wrap and MIC tokens

#[cfg(test)]
mod interop; // MIT krb5 interop fixtures — the gate vectors cannot close

pub use acceptor::{
    EncType, KerberosContext, KerberosError, Keytab, Result, ServiceKey,
    DEFAULT_CLOCK_SKEW_SECS,
};
