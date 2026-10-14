//! ONC RPC (RFC 5531) over TCP, authenticated and encrypted by RPCSEC_GSS
//! (RFC 2203) with the Kerberos GSS-API mechanism, as MIT's kadmin client
//! uses it (`authgss_create` with `RPCSEC_GSS_SVC_PRIVACY`).
//!
//! The context is made with NULLPROC calls carrying the GSS tokens
//! (`RPCSEC_GSS_INIT`); the server's last reply carries a MIC over the
//! sequence window, which proves it holds the context. Every call after
//! that carries a credential with the next sequence number and, as its
//! verifier, a MIC over the RPC header; its arguments travel sealed in a
//! GSS Wrap token, behind the same sequence number. The reply's verifier
//! is the server's MIC over that number, and its sealed results must
//! carry it too, so a reply cannot be replayed or moved to another call.

use super::xdr::{Reader, Writer};
use super::{Error, Result};
use crate::client::Credentials;
use crate::initiator::{GSS_C_MUTUAL_FLAG, InitiatorContext};
use crate::token::{ContextKey, PerMessageTokens};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// `GSS_C_REPLAY_FLAG`, which MIT's client also asks for.
const GSS_C_REPLAY_FLAG: u32 = 4;

const RPC_VERSION: u32 = 2;
const CALL: u32 = 0;
const REPLY: u32 = 1;
const AUTH_NONE: u32 = 0;
const RPCSEC_GSS: u32 = 6;
const RPCSEC_GSS_VERSION: u32 = 1;
const RPCSEC_GSS_DATA: u32 = 0;
const RPCSEC_GSS_INIT: u32 = 1;
const RPCSEC_GSS_DESTROY: u32 = 3;
const RPCSEC_GSS_SVC_PRIVACY: u32 = 3;
const GSS_S_COMPLETE: u32 = 0;
const NULLPROC: u32 = 0;
/// The largest reply accepted.
const MAX_REPLY: usize = 16 << 20;

/// An RPC connection to one program and version, with an established
/// RPCSEC_GSS context.
pub(crate) struct Client {
    stream: TcpStream,
    prog: u32,
    vers: u32,
    xid: u32,
    tokens: PerMessageTokens<ContextKey>,
    /// The next GSS sequence number for our tokens.
    gss_seq: u64,
    /// The context handle the server gave, and the RPCSEC_GSS sequence.
    handle: Vec<u8>,
    seq: u32,
    window: u32,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("rpc::Client")
            .field("peer", &self.stream.peer_addr().ok())
            .field("prog", &self.prog)
            .field("seq", &self.seq)
            .finish()
    }
}

/// An RPC message over TCP: record marking (RFC 5531 §11), each fragment
/// a four-octet header, its top bit marking the last.
fn send_record(s: &mut TcpStream, msg: &[u8]) -> Result<()> {
    let mut out = Vec::with_capacity(msg.len() + 4);
    out.extend_from_slice(&(0x8000_0000 | msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    s.write_all(&out).map_err(Error::Io)
}

fn recv_record(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut msg = Vec::new();
    loop {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).map_err(Error::Io)?;
        let h = u32::from_be_bytes(h);
        let len = (h & 0x7FFF_FFFF) as usize;
        if msg.len() + len > MAX_REPLY {
            return Err(Error::Protocol("RPC reply too large".into()));
        }
        let start = msg.len();
        msg.resize(start + len, 0);
        s.read_exact(&mut msg[start..]).map_err(Error::Io)?;
        if h & 0x8000_0000 != 0 {
            return Ok(msg);
        }
    }
}

/// The RPC call header: xid, CALL, version 2, program, version,
/// procedure, and the credential.
fn call_header(
    xid: u32,
    prog: u32,
    vers: u32,
    proc_: u32,
    cred_flavor: u32,
    cred: &[u8],
) -> Writer {
    let mut w = Writer::new();
    w.u32(xid)
        .u32(CALL)
        .u32(RPC_VERSION)
        .u32(prog)
        .u32(vers)
        .u32(proc_)
        .u32(cred_flavor)
        .opaque(cred);
    w
}

fn gss_cred(gss_proc: u32, seq: u32, handle: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(RPCSEC_GSS_VERSION)
        .u32(gss_proc)
        .u32(seq)
        .u32(RPCSEC_GSS_SVC_PRIVACY)
        .opaque(handle);
    w.0
}

/// An accepted reply's verifier and results, after checking the xid.
fn parse_reply(msg: &[u8], xid: u32) -> Result<(u32, Vec<u8>, Vec<u8>)> {
    let mut r = Reader::new(msg);
    if r.u32()? != xid {
        return Err(Error::Protocol("RPC reply to another call".into()));
    }
    if r.u32()? != REPLY {
        return Err(Error::Protocol("RPC message is not a reply".into()));
    }
    match r.u32()? {
        0 => {}
        1 => {
            return Err(match r.u32()? {
                0 => Error::Rpc(format!(
                    "server speaks RPC versions {} to {} only",
                    r.u32()?,
                    r.u32()?
                )),
                _ => Error::Rpc(format!(
                    "authentication refused ({})",
                    match r.u32()? {
                        1 => "bad credential".to_string(),
                        2 => "credential rejected".to_string(),
                        13 => "RPCSEC_GSS credential problem".to_string(),
                        14 => "RPCSEC_GSS context problem".to_string(),
                        n => format!("auth_stat {n}"),
                    }
                )),
            });
        }
        n => return Err(Error::Protocol(format!("RPC reply_stat {n}"))),
    }
    let flavor = r.u32()?;
    let verf = r.opaque()?.to_vec();
    match r.u32()? {
        0 => Ok((flavor, verf, r.rest().to_vec())),
        1 => Err(Error::Rpc("program unavailable".into())),
        2 => Err(Error::Rpc("program version unavailable".into())),
        3 => Err(Error::Rpc("procedure unavailable".into())),
        4 => Err(Error::Rpc(
            "the server could not decode the arguments".into(),
        )),
        n => Err(Error::Rpc(format!("server error (accept_stat {n})"))),
    }
}

impl Client {
    /// Connect to `addr`, and make the RPCSEC_GSS context for `creds`, a
    /// ticket for the server's principal.
    pub(crate) fn connect(
        addr: &str,
        prog: u32,
        vers: u32,
        creds: &Credentials,
        timeout: Duration,
    ) -> Result<Client> {
        let sock = std::net::ToSocketAddrs::to_socket_addrs(addr)
            .map_err(Error::Io)?
            .next()
            .ok_or_else(|| Error::Rpc(format!("{addr}: no address")))?;
        let mut stream = TcpStream::connect_timeout(&sock, timeout).map_err(Error::Io)?;
        stream.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
        stream.set_write_timeout(Some(timeout)).map_err(Error::Io)?;
        let _ = stream.set_nodelay(true);

        let (mut ctx, token) = InitiatorContext::new(creds, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG)
            .map_err(Error::Client)?;
        let xid = rand::random::<u32>();
        let cred = gss_cred(RPCSEC_GSS_INIT, 0, &[]);
        let mut call = call_header(xid, prog, vers, NULLPROC, RPCSEC_GSS, &cred);
        call.u32(AUTH_NONE).opaque(&[]).opaque(&token);
        send_record(&mut stream, &call.0)?;
        let (flavor, verf, body) = parse_reply(&recv_record(&mut stream)?, xid)?;

        // rpc_gss_init_res ::= { handle, gss_major, gss_minor, seq_window, gss_token }
        let mut r = Reader::new(&body);
        let handle = r.opaque()?.to_vec();
        let major = r.u32()?;
        let minor = r.u32()?;
        let window = r.u32()?;
        let reply_token = r.opaque()?.to_vec();
        if major != GSS_S_COMPLETE {
            return Err(Error::Rpc(format!(
                "the server refused the GSS context (major {major:#x}, minor {minor})"
            )));
        }
        ctx.step(&reply_token).map_err(Error::Client)?;
        let tokens = ctx.per_message_tokens().map_err(Error::Client)?;
        // RFC 2203 §5.2.3.1: the final reply's verifier is the server's
        // MIC over the window.
        if flavor != RPCSEC_GSS {
            return Err(Error::Protocol(
                "the server's context reply has no RPCSEC_GSS verifier".into(),
            ));
        }
        tokens
            .verify_mic(&verf, &window.to_be_bytes())
            .map_err(|e| Error::Protocol(format!("the server's context verifier: {e}")))?;
        Ok(Client {
            stream,
            prog,
            vers,
            xid: xid.wrapping_add(1),
            gss_seq: ctx.send_seq(),
            tokens,
            handle,
            seq: 0,
            window,
        })
    }

    fn next_gss_seq(&mut self) -> u64 {
        let s = self.gss_seq;
        self.gss_seq = self.gss_seq.wrapping_add(1);
        s
    }

    /// Call procedure `proc_` with XDR `args`, and return its XDR results.
    pub(crate) fn call(&mut self, proc_: u32, args: &[u8]) -> Result<Vec<u8>> {
        self.seq = self.seq.wrapping_add(1);
        let (seq, xid) = (self.seq, self.xid);
        self.xid = self.xid.wrapping_add(1);
        let cred = gss_cred(RPCSEC_GSS_DATA, seq, &self.handle);
        let header = call_header(xid, self.prog, self.vers, proc_, RPCSEC_GSS, &cred);
        let s1 = self.next_gss_seq();
        let mic = self.tokens.emit_mic(s1, &header.0).map_err(token_err)?;
        let mut body = Writer::new();
        body.u32(seq).raw(args);
        let s2 = self.next_gss_seq();
        let sealed = self.tokens.emit_wrap(s2, &body.0).map_err(token_err)?;
        let mut msg = header;
        msg.u32(RPCSEC_GSS).opaque(&mic).opaque(&sealed);
        send_record(&mut self.stream, &msg.0)?;

        let (flavor, verf, results) = parse_reply(&recv_record(&mut self.stream)?, xid)?;
        if flavor != RPCSEC_GSS {
            return Err(Error::Protocol(
                "reply without an RPCSEC_GSS verifier".into(),
            ));
        }
        self.tokens
            .verify_mic(&verf, &seq.to_be_bytes())
            .map_err(|e| Error::Protocol(format!("reply verifier: {e}")))?;
        let mut r = Reader::new(&results);
        let sealed = r.opaque()?;
        let plain = self.tokens.unwrap(sealed).map_err(token_err)?.message;
        let mut p = Reader::new(&plain);
        if p.u32()? != seq {
            return Err(Error::Protocol(
                "reply sealed for another call (sequence number)".into(),
            ));
        }
        Ok(p.rest().to_vec())
    }

    /// The server's sequence window, for the record.
    #[allow(dead_code)]
    pub(crate) fn window(&self) -> u32 {
        self.window
    }

    /// RPCSEC_GSS_DESTROY: tell the server to drop the context. Best
    /// effort; errors are ignored, as MIT ignores them.
    pub(crate) fn destroy(&mut self) {
        self.seq = self.seq.wrapping_add(1);
        let (seq, xid) = (self.seq, self.xid);
        let cred = gss_cred(RPCSEC_GSS_DESTROY, seq, &self.handle);
        let header = call_header(xid, self.prog, self.vers, NULLPROC, RPCSEC_GSS, &cred);
        let s = self.next_gss_seq();
        if let Ok(mic) = self.tokens.emit_mic(s, &header.0) {
            let mut msg = header;
            msg.u32(RPCSEC_GSS).opaque(&mic);
            if send_record(&mut self.stream, &msg.0).is_ok() {
                let _ = recv_record(&mut self.stream);
            }
        }
    }
}

fn token_err(e: crate::token::TokenError) -> Error {
    Error::Protocol(format!("GSS token: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_headers_are_rfc_5531() {
        let h = call_header(7, 2112, 2, 5, RPCSEC_GSS, &[1, 2, 3]);
        assert_eq!(
            h.0,
            [
                0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 8, 64, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0,
                6, 0, 0, 0, 3, 1, 2, 3, 0
            ]
        );
        let c = gss_cred(RPCSEC_GSS_DATA, 9, &[0xAA; 4]);
        assert_eq!(
            c,
            [
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 4, 0xAA, 0xAA, 0xAA, 0xAA
            ]
        );
    }

    #[test]
    fn replies_are_checked_before_use() {
        let mut ok = Writer::new();
        ok.u32(5)
            .u32(REPLY)
            .u32(0)
            .u32(RPCSEC_GSS)
            .opaque(b"mic")
            .u32(0)
            .raw(b"results");
        let (f, v, r) = parse_reply(&ok.0, 5).unwrap();
        assert_eq!(
            (f, v.as_slice(), r.as_slice()),
            (RPCSEC_GSS, &b"mic"[..], &b"results"[..])
        );
        assert!(parse_reply(&ok.0, 6).is_err(), "another xid");
        let mut denied = Writer::new();
        denied.u32(5).u32(REPLY).u32(1).u32(1).u32(14);
        let e = parse_reply(&denied.0, 5).unwrap_err().to_string();
        assert!(e.contains("context problem"), "{e}");
        let mut garbage = Writer::new();
        garbage.u32(5).u32(REPLY).u32(0).u32(0).opaque(&[]).u32(4);
        assert!(
            parse_reply(&garbage.0, 5)
                .unwrap_err()
                .to_string()
                .contains("decode")
        );
    }
}
