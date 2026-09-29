//! The protocol between agent and SPIFFE server (ADR-0006, ADR-0037).
//!
//! # Why it stands here and not in `tgd`
//!
//! Both sides need the same message types, and two copies would be two
//! opportunities to let them go apart. The obvious place would be the server side --
//! but then `tg-agent` would hang on `tgd` and thereby on the consensus core: the
//! node agent would link `openraft` and `redb` in order to fetch a certificate. That
//! is no question of size but of layering.
//!
//! `tg-identity` is the place both hang on anyway. Here lie the types and the
//! client; the service stays in `tgd`, where it reaches the Raft log.
//!
//! The codec lay here too until the third occurrence. It now lies in [`tg_wire`] --
//! the same consideration, one layer deeper: the message types are the protocol, the
//! codec is the adapter, and an adapter three paths need belongs below all three.
//!
//! # The sequence
//!
//! ```text
//! Join      { node, token, spki, underlay? }              -> node SVID + bundle
//! Challenge { node }                                      -> nonce
//! Renew     { node, nonce, signature, spki, underlay? }   -> node SVID + intermediate
//! ```
//!
//! `Join` happens **once**. Afterwards the key is the identity, and the token is
//! worthless (ADR-0037).
//!
//! # The underlay announcement (ADR-0042)
//!
//! It travels along here, and not on the stream from ADR-0040. The reason is the
//! authorization: **this is the only way on which a node identifies itself.** On the
//! stream its name is to this day a self-declaration (mTLS has been missing since
//! phase 5c), and a node could announce another's key there.
//!
//! From that follows [`renew_message`]: the signature covers **everything it
//! authorizes**, not only the nonce.
//!
//! # Why no `deny_unknown_fields` stands here
//!
//! ADR-0072 decided the strictness of the session messages, ADR-0083 that of the
//! admin service -- **no** type of this module carries the attribute, and that is
//! measured to be right. A reader who comes from those ADRs ("strict everywhere")
//! would otherwise see a gap here:
//!
//! - **`RenewRequest` is structurally healed.** The signature covers the **request**
//!   (ADR-0046), so the server serializes a different one if it discards a field --
//!   the signature does not fit, and the request is refused. Fail-closed, without an
//!   attribute.
//! - **`JoinRequest` is unsigned, with a reason** (ADR-0042): whoever can alter it
//!   can just as well swap the `spki` -- then they *are* the node. A discarded field
//!   means **less** there, not more: a missing underlay announcement stands out at
//!   the comparison (ADR-0042).
//! - **`Credentials` is the answer**, and here leniency is the decision. Unlike at
//!   `tgctl`/`tgd` (ADR-0083, one build on one machine), agent and `tgd` are
//!   **different processes with a rolling update** (ADR-0031). Strict would mean
//!   that an old agent can no longer join against a new `tgd` -- an outage window
//!   precisely in the bootstrap path. What an agent does not know costs it **less**:
//!   no data key means no secrets, no ordinal means no network, and both are
//!   fail-closed and visible.

use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

pub const IDENTITY_SERVICE: &str = "tardigrade.identity.v1.Identity";
pub const JOIN: &str = "/tardigrade.identity.v1.Identity/Join";
pub const CHALLENGE: &str = "/tardigrade.identity.v1.Identity/Challenge";
pub const RENEW: &str = "/tardigrade.identity.v1.Identity/Renew";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Underlay {
    pub key: String,
    pub endpoint: String,
}

#[must_use]
pub fn renew_message(request: &RenewRequest) -> Vec<u8> {
    let mut out = Vec::new();

    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        out.extend_from_slice(bytes);
    };

    field(request.node.as_bytes());
    field(request.nonce.as_bytes());
    field(request.intermediate_spki.as_bytes());
    // The **absence counts along**, as at the announcement: otherwise a rotation
    // could be appended or struck without breaking the signature -- and whoever
    // intercepted a request would swap the node's identity (ADR-0055).
    match &request.next_node_spki {
        Some(spki) => {
            field(&[1]);
            field(spki.as_bytes());
        }
        None => field(&[0]),
    }
    match &request.underlay {
        Some(underlay) => {
            field(&[1]);
            field(underlay.key.as_bytes());
            field(underlay.endpoint.as_bytes());
        }
        None => field(&[0]),
    }

    out
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRequest {
    pub node: String,
    pub token: String,
    pub spki: String,
    #[serde(default)]
    pub underlay: Option<Underlay>,
}

impl std::fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinRequest")
            .field("node", &self.node)
            .field("spki", &self.spki)
            .field("underlay", &self.underlay)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewRequest {
    pub node: String,
    pub nonce: String,
    pub signature: String,
    pub intermediate_spki: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_node_spki: Option<String>,

    #[serde(default)]
    pub underlay: Option<Underlay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Credentials {
    Issued {
        node_svid_pem: String,
        intermediate_pem: Option<String>,
        bundle_pem: String,
        #[serde(default)]
        ordinal: Option<u32>,
        #[serde(default)]
        data_key: Option<String>,
        #[serde(default)]
        previous_data_key: Option<String>,
    },
    Refused {
        reason: String,
    },
    ForwardTo {
        leader: Option<u64>,
    },
}

#[derive(Debug, Clone)]
pub struct IdentityClient {
    channel: tonic::transport::Channel,
}

impl IdentityClient {
    #[must_use]
    pub fn with_channel(channel: tonic::transport::Channel) -> Self {
        Self { channel }
    }

    pub async fn join(&self, request: JoinRequest) -> Result<Credentials, Status> {
        self.unary(JOIN, request).await
    }

    pub async fn challenge(&self, node: &str) -> Result<ChallengeResponse, Status> {
        self.unary(
            CHALLENGE,
            ChallengeRequest {
                node: node.to_owned(),
            },
        )
        .await
    }

    pub async fn renew(&self, request: RenewRequest) -> Result<Credentials, Status> {
        self.unary(RENEW, request).await
    }

    async fn unary<Req, Resp>(&self, path: &'static str, request: Req) -> Result<Resp, Status>
    where
        Req: Serialize + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        // **Without a raised message limit**, and that deliberately: this port's
        // answers are certificates and nonces, so small -- and the port demands no
        // client certificate (ADR-0043, determination 3). The default of 4 MiB is a
        // bound there and no shortcoming.
        let mut client = tonic::client::Grpc::new(self.channel.clone());
        client
            .ready()
            .await
            .map_err(|err| Status::unavailable(err.to_string()))?;

        client
            .unary(
                Request::new(request),
                http::uri::PathAndQuery::from_static(path),
                tg_wire::JsonCodec::<Req, Resp>::default(),
            )
            .await
            .map(Response::into_inner)
    }
}

#[must_use]
pub fn spki_base64(key: &rcgen::KeyPair) -> String {
    use rcgen::PublicKeyData as _;

    base64(&key.subject_public_key_info())
}

#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;

    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn unbase64(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;

    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|err| format!("no base64: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{base64, unbase64};

    #[test]
    fn the_reader_is_strict_up_to_whitespace() {
        // What holds holds on.
        assert_eq!(unbase64("QUJD").as_deref(), Ok(b"ABC".as_slice()));
        assert_eq!(unbase64("QQ==").as_deref(), Ok(b"A".as_slice()));
        assert_eq!(unbase64("").as_deref(), Ok(b"".as_slice()));

        // Whitespace is formatting -- a wrapped text stays readable.
        assert_eq!(unbase64("QUJD\n").as_deref(), Ok(b"ABC".as_slice()));
        assert_eq!(unbase64(" QU\tJD ").as_deref(), Ok(b"ABC".as_slice()));

        // **And this is new**: everything below it silently yielded bytes until
        // now, and the same ones as another text.
        for lax in ["QUJ", "QUJ=", "QUJD=", "QUJD!", "QUJD==="] {
            assert!(
                unbase64(lax).is_err(),
                "'{lax}' was accepted -- then two different texts yield the same \
                 bytes (ADR-0087)"
            );
        }
    }

    #[test]
    fn the_encoder_writes_what_it_always_wrote() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"A"), "QQ==");
        assert_eq!(base64(b"AB"), "QUI=");
        assert_eq!(base64(b"ABC"), "QUJD");
        assert_eq!(base64(b"ABCD"), "QUJDRA==");
        // All 64 characters of the alphabet, `+` and `/` included.
        assert_eq!(base64(&[0xFB, 0xFF, 0xFE]), "+//+");
    }

    #[test]
    fn the_round_trip_holds_for_every_remainder() {
        for len in 0..12_usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();
            let text = base64(&bytes);
            assert_eq!(
                unbase64(&text).as_deref(),
                Ok(bytes.as_slice()),
                "length {len}: {text:?}"
            );
        }
    }
}
