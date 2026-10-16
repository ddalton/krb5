//! User-to-user (RFC 4120 §2.9.2, MIT's `kvno --u2u`): a ticket a server
//! decrypts with the session key of its own TGT rather than a long-term
//! key, for servers that have no keytab (a user's desktop, say). The
//! server sends its TGT's ticket to the client, the client asks the KDC
//! for a ticket encrypted in that TGT's session key (ENC-TKT-IN-SKEY,
//! with the TGT as the additional ticket), and the server accepts it with
//! [`KerberosContext::accept_token_u2u`] or
//! [`KerberosContext::accept_ap_req_u2u`].
//!
//! [`KerberosContext::accept_token_u2u`]: crate::KerberosContext::accept_token_u2u
//! [`KerberosContext::accept_ap_req_u2u`]: crate::KerberosContext::accept_ap_req_u2u

use super::*;

/// KDCOptions enc-tkt-in-skey (bit 28).
const KDC_OPT_ENC_TKT_IN_SKEY: u32 = 1 << 3;

impl KdcClient {
    /// A user-to-user ticket for `server`, encrypted in the session key of
    /// `server_tgt` (the server's TGT, its ticket as the server sent it;
    /// the session key stays with the server), through `tgt`, the client's
    /// own TGT. The KDC issues it only if `server` is the client of
    /// `server_tgt` (or an alias of it) and the server allows duplicate
    /// session keys (MIT's `allow_dup_skey`, on by default).
    ///
    /// `server` with an empty realm is in `tgt`'s realm. Both TGTs must be
    /// for that realm: cross-realm user-to-user is not supported.
    pub fn user_to_user(
        &self,
        tgt: &Credentials,
        server: &Principal,
        server_tgt: &[u8],
    ) -> Result<Credentials> {
        block_on(self.user_to_user_on(&Blocking, tgt, server, server_tgt))
    }

    pub(crate) async fn user_to_user_on<N: Net>(
        &self,
        net: &N,
        tgt: &Credentials,
        server: &Principal,
        server_tgt: &[u8],
    ) -> Result<Credentials> {
        let realm = tgt_realm(tgt).to_string();
        let mut server = server.clone();
        if server.realm.is_empty() {
            server.realm = realm.clone();
        }
        let theirs = ticket_server(server_tgt)
            .ok_or_else(|| ClientError::Protocol("the server's TGT does not parse".into()))?;
        if !same_principal(&theirs, &Principal::krbtgt(&realm)) || server.realm != realm {
            return Err(ClientError::Protocol(format!(
                "user-to-user with {server}, whose TGT is for {theirs}, through a TGT for \
                 {realm}: cross-realm user-to-user is not supported"
            )));
        }
        self.tgs_ext(
            net,
            &realm,
            tgt,
            &server,
            KDC_OPT_ENC_TKT_IN_SKEY,
            &S4u::UserToUser(server_tgt),
        )
        .await
        .map(|r| r.creds)
    }
}

/// The server a Ticket names (its realm and sname).
pub(super) fn ticket_server(ticket: &[u8]) -> Option<Principal> {
    let tf = Fields::parse_tagged("Ticket", app(1), ticket).ok()?;
    let realm = tf.get(1).ok()?.string().ok()?;
    Principal::decode_name(tf.get(2).ok()?, realm).ok()
}
