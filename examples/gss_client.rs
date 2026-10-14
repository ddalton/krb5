//! A minimal GSS-API client: log in, get a service ticket, establish a
//! context with mutual authentication, and exchange one Wrap token each
//! way. Tokens are hex lines on stdout/stdin, so any acceptor can sit on
//! the other end (`scripts/mit-acceptor.py` drives MIT's libgssapi).
//!
//!     gss_client <kdc host:port> <client@REALM> <password> <service@REALM>
//!
//! `GSS_CLIENT_ENCTYPE=<17-20>` restricts the requested session enctype.
//!
//! Protocol: prints the AP-REQ token, reads the AP-REP, prints a Wrap of
//! "ping", reads a Wrap that must contain "pong", prints "ok".

use krb5::initiator::{GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
use krb5::{InitiatorContext, KdcClient, Principal};
use std::io::BufRead;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, kdc, client, password, service] = &args[..] else {
        return Err("usage: gss_client <kdc> <client@REALM> <password> <service@REALM>".into());
    };
    let client = Principal::parse(client)?;
    let service = Principal::parse(service)?;
    let mut kdc = KdcClient::new(client.realm.clone(), [kdc.as_str()]);
    if let Ok(et) = std::env::var("GSS_CLIENT_ENCTYPE") {
        kdc = kdc.with_enctypes(&[et.parse()?]);
    }

    let tgt = kdc.login_with_password(&client, password)?;
    let creds = kdc.service_ticket(&tgt, &service)?;
    eprintln!(
        "service ticket for {}: ticket enctype {}, session enctype {}",
        creds.server,
        creds.ticket_enctype,
        creds.session_key.enctype()
    );

    let (mut ctx, token) = InitiatorContext::new(
        &creds,
        GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG,
    )?;
    println!("{}", hex(&token));

    let mut lines = std::io::stdin().lock().lines();
    let mut next = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(unhex(&lines.next().ok_or("acceptor hung up")??))
    };
    ctx.step(&next()?)?;
    eprintln!(
        "established; acceptor subkey: {}",
        ctx.has_acceptor_subkey()
    );

    let tokens = ctx.per_message_tokens()?;
    println!("{}", hex(&tokens.emit_wrap(ctx.send_seq(), b"ping")?));
    let reply = tokens.unwrap(&next()?)?;
    if reply.message != b"pong" {
        return Err(format!("expected pong, got {:?}", reply.message).into());
    }
    println!("ok");
    Ok(())
}
