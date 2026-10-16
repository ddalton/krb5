//! [`AsyncKdcClient`]: the KDC client on tokio (the `tokio` feature).

use super::*;
use crate::net::Tokio;

/// A [`KdcClient`] whose exchanges run on tokio: the same requests, the
/// same checks and the same transport choices (UDP or TCP, MIT's retries
/// and waits), with tokio's sockets and timers in place of blocking ones,
/// so a login or a service ticket holds no thread while it waits for a
/// KDC. Every future is `Send`.
///
/// Make one from a configured [`KdcClient`], or with
/// [`AsyncKdcClient::from_config`] / [`AsyncKdcClient::discover`], which
/// look a realm's KDCs up in DNS without blocking. It runs on the
/// runtime it is awaited in, which needs tokio's I/O and time drivers
/// (`#[tokio::main]`, or a `Runtime` built with `enable_all`).
///
/// The methods that read or write a credential cache
/// ([`AsyncKdcClient::service_ticket_cached`], the `kinit_*` ones) do so
/// in place, as [`KdcClient`]'s do: a local file, or a request to the KCM
/// daemon over a Unix socket. Only the KDC exchanges are asynchronous.
///
/// ```no_run
/// # async fn f() -> Result<(), Box<dyn std::error::Error>> {
/// use krb5::{AsyncKdcClient, KdcClient, Principal};
///
/// let kdc = AsyncKdcClient::discover("EXAMPLE.COM").await?;
/// // or: AsyncKdcClient::new(KdcClient::new("EXAMPLE.COM", ["kdc.example.com"]))
/// let me = Principal::parse("alice@EXAMPLE.COM")?;
/// let tgt = kdc.login_with_password(&me, "secret").await?;
/// let service = Principal::parse("HTTP/www.example.com@EXAMPLE.COM")?;
/// let creds = kdc.service_ticket(&tgt, &service).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct AsyncKdcClient {
    kdc: KdcClient,
}

impl From<KdcClient> for AsyncKdcClient {
    fn from(kdc: KdcClient) -> Self {
        AsyncKdcClient { kdc }
    }
}

impl AsyncKdcClient {
    /// `kdc`, with its realm, KDCs and settings, on tokio.
    pub fn new(kdc: KdcClient) -> Self {
        AsyncKdcClient { kdc }
    }

    /// The client's settings: its realm, KDCs and the rest.
    pub fn client(&self) -> &KdcClient {
        &self.kdc
    }

    /// The blocking client, with the same settings.
    pub fn into_client(self) -> KdcClient {
        self.kdc
    }

    /// [`KdcClient::from_config`], asking DNS for the realm's KDCs (when
    /// `krb5.conf` names none) without blocking.
    pub async fn from_config(conf: &Krb5Conf, realm: &str) -> config::Result<Self> {
        KdcClient::from_config_on(&Tokio, conf, realm, None)
            .await
            .map(Self::new)
    }

    /// [`KdcClient::from_config_with_resolver`].
    pub async fn from_config_with_resolver(
        conf: &Krb5Conf,
        realm: &str,
        resolver: &Resolver,
    ) -> config::Result<Self> {
        KdcClient::from_config_on(&Tokio, conf, realm, Some(resolver))
            .await
            .map(Self::new)
    }

    /// [`KdcClient::discover`]: the `KRB5_CONFIG` files (else
    /// `/etc/krb5.conf`), then DNS.
    pub async fn discover(realm: &str) -> config::Result<Self> {
        Self::from_config(&Krb5Conf::load_default()?, realm).await
    }

    /// [`KdcClient::for_realm`].
    pub async fn for_realm(&self, realm: &str) -> Result<AsyncKdcClient> {
        self.kdc.for_realm_with(&Tokio, realm).await.map(Self::new)
    }

    /// [`KdcClient::login_with_password`].
    pub async fn login_with_password(
        &self,
        client: &Principal,
        password: &str,
    ) -> Result<Credentials> {
        self.kdc
            .login_with_password_on(&Tokio, client, password)
            .await
    }

    /// [`KdcClient::login_with_keytab`].
    pub async fn login_with_keytab(
        &self,
        client: &Principal,
        keytab: &Keytab,
    ) -> Result<Credentials> {
        self.kdc.login_with_keytab_on(&Tokio, client, keytab).await
    }

    /// [`KdcClient::login_with_otp`].
    pub async fn login_with_otp(&self, client: &Principal, value: &str) -> Result<Credentials> {
        self.kdc
            .login_with_otp_on(&Tokio, client, &|ch| otp::answer_with(ch, value))
            .await
    }

    /// [`KdcClient::login_with_otp_by`].
    pub async fn login_with_otp_by(
        &self,
        client: &Principal,
        answer: impl Fn(&otp::OtpChallenge) -> Result<otp::OtpAnswer> + Sync,
    ) -> Result<Credentials> {
        self.kdc.login_with_otp_on(&Tokio, client, &answer).await
    }

    /// [`KdcClient::kinit_with_password`].
    pub async fn kinit_with_password(
        &self,
        client: &Principal,
        password: &str,
        cache: &CacheName,
    ) -> Result<Credentials> {
        self.kdc
            .kinit_with_password_on(&Tokio, client, password, cache)
            .await
    }

    /// [`KdcClient::kinit_with_keytab`].
    pub async fn kinit_with_keytab(
        &self,
        client: &Principal,
        keytab: &Keytab,
        cache: &CacheName,
    ) -> Result<Credentials> {
        self.kdc
            .kinit_with_keytab_on(&Tokio, client, keytab, cache)
            .await
    }

    /// [`KdcClient::login_anonymous`].
    #[cfg(feature = "pkinit")]
    pub async fn login_anonymous(&self) -> Result<Credentials> {
        self.kdc
            .anonymous(&Tokio, &self.kdc.realm)
            .await
            .map(|(c, _)| c)
    }

    /// [`KdcClient::kinit_anonymous`].
    #[cfg(feature = "pkinit")]
    pub async fn kinit_anonymous(&self, cache: &CacheName) -> Result<Credentials> {
        self.kdc.kinit_anonymous_on(&Tokio, cache).await
    }

    /// [`KdcClient::login_with_certificate`].
    #[cfg(feature = "pkinit")]
    pub async fn login_with_certificate(
        &self,
        client: &Principal,
        identity: &pkinit::Identity,
    ) -> Result<Credentials> {
        self.kdc
            .login_with_certificate_on(&Tokio, client, identity)
            .await
    }

    /// [`KdcClient::kinit_with_certificate`].
    #[cfg(feature = "pkinit")]
    pub async fn kinit_with_certificate(
        &self,
        client: &Principal,
        identity: &pkinit::Identity,
        cache: &CacheName,
    ) -> Result<Credentials> {
        self.kdc
            .kinit_with_certificate_on(&Tokio, client, identity, cache)
            .await
    }

    /// [`KdcClient::initial_ticket_with_password`].
    pub async fn initial_ticket_with_password(
        &self,
        client: &Principal,
        password: &str,
        service: &Principal,
    ) -> Result<Credentials> {
        self.kdc
            .initial_ticket_with_password_on(&Tokio, client, password, service)
            .await
    }

    /// [`KdcClient::initial_ticket_with_keytab`].
    pub async fn initial_ticket_with_keytab(
        &self,
        client: &Principal,
        keytab: &Keytab,
        service: &Principal,
    ) -> Result<Credentials> {
        self.kdc
            .initial_ticket_with_keytab_on(&Tokio, client, keytab, service)
            .await
    }

    /// [`KdcClient::service_ticket`].
    pub async fn service_ticket(
        &self,
        tgt: &Credentials,
        service: &Principal,
    ) -> Result<Credentials> {
        self.kdc.get_creds(&Tokio, tgt, service, &mut NoStore).await
    }

    /// [`KdcClient::service_ticket_cached`].
    pub async fn service_ticket_cached(
        &self,
        cache: &CacheName,
        service: &Principal,
    ) -> Result<Credentials> {
        self.kdc
            .service_ticket_cached_on(&Tokio, cache, service)
            .await
    }

    /// [`KdcClient::forwarded_tgt`].
    pub async fn forwarded_tgt(
        &self,
        tgt: &Credentials,
        enctype: Option<i32>,
    ) -> Result<Credentials> {
        self.kdc.forwarded_tgt_on(&Tokio, tgt, enctype).await
    }

    /// [`KdcClient::renew`].
    pub async fn renew(&self, creds: &Credentials) -> Result<Credentials> {
        self.kdc.renew_on(&Tokio, creds).await
    }

    /// [`KdcClient::validate`].
    pub async fn validate(&self, creds: &Credentials) -> Result<Credentials> {
        self.kdc.validate_on(&Tokio, creds).await
    }

    /// [`KdcClient::kinit_renew`].
    pub async fn kinit_renew(&self, cache: &CacheName) -> Result<Credentials> {
        self.kdc.kinit_again(&Tokio, cache, KDC_OPT_RENEW).await
    }

    /// [`KdcClient::kinit_validate`].
    pub async fn kinit_validate(&self, cache: &CacheName) -> Result<Credentials> {
        self.kdc.kinit_again(&Tokio, cache, KDC_OPT_VALIDATE).await
    }

    /// [`KdcClient::s4u2self`].
    pub async fn s4u2self(&self, tgt: &Credentials, user: &Principal) -> Result<Credentials> {
        self.kdc.s4u2self_on(&Tokio, tgt, user).await
    }

    /// [`KdcClient::s4u2proxy`].
    pub async fn s4u2proxy(
        &self,
        tgt: &Credentials,
        evidence: &Credentials,
        target: &Principal,
    ) -> Result<Credentials> {
        self.kdc.s4u2proxy_on(&Tokio, tgt, evidence, target).await
    }

    /// [`KdcClient::user_to_user`].
    pub async fn user_to_user(
        &self,
        tgt: &Credentials,
        server: &Principal,
        server_tgt: &[u8],
    ) -> Result<Credentials> {
        self.kdc
            .user_to_user_on(&Tokio, tgt, server, server_tgt)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send<T: Send>(_: T) {}

    /// Every future is `Send`, so it can be spawned on a multi-threaded
    /// runtime. Compiled, never run.
    #[allow(dead_code)]
    fn futures_are_send(
        c: &AsyncKdcClient,
        p: &Principal,
        k: &Keytab,
        cc: &CacheName,
        t: &Credentials,
        #[cfg(feature = "pkinit")] id: &pkinit::Identity,
    ) {
        let conf = Krb5Conf::empty();
        send(AsyncKdcClient::from_config(&conf, "R"));
        send(AsyncKdcClient::discover("R"));
        send(c.for_realm("R"));
        send(c.login_with_password(p, "pw"));
        send(c.login_with_keytab(p, k));
        send(c.login_with_otp(p, "123"));
        send(c.login_with_otp_by(p, |ch| otp::answer_with(ch, "1")));
        send(c.kinit_with_password(p, "pw", cc));
        send(c.kinit_with_keytab(p, k, cc));
        send(c.initial_ticket_with_password(p, "pw", p));
        send(c.initial_ticket_with_keytab(p, k, p));
        send(c.service_ticket(t, p));
        send(c.service_ticket_cached(cc, p));
        send(c.forwarded_tgt(t, None));
        send(c.renew(t));
        send(c.validate(t));
        send(c.kinit_renew(cc));
        send(c.kinit_validate(cc));
        send(c.s4u2self(t, p));
        send(c.s4u2proxy(t, t, p));
        send(c.user_to_user(t, p, &[]));
        send(crate::kpasswd::change_password_async(c, p, "a", "b", "s"));
        send(crate::kpasswd::change_password_with_ticket_async(
            t, "b", "s",
        ));
        send(crate::kpasswd::set_password_async(t, p, "b", "s"));
        #[cfg(feature = "pkinit")]
        {
            send(c.login_anonymous());
            send(c.kinit_anonymous(cc));
            send(c.login_with_certificate(p, id));
            send(c.kinit_with_certificate(p, id, cc));
        }
    }
}
