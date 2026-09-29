//! The JSON payload of the internal gRPC paths — **one** codec, not three.
//!
//! gRPC prescribes HTTP/2, the message framing and the status codes, not the
//! payload format. All three internal paths use the same [`tonic::codec::Codec`]:
//! JSON over `serde`. Chosen over protobuf so that what goes over the wire is
//! byte for byte what stands in the audit log and so that no second toolchain
//! has to be guarded against drift. The price: `grpcurl` and reflection do not
//! work on these services.
//!
//! It is a crate and not three copies because the copies **had** diverged where
//! it counts: one reported an unreadable foreign message as `internal` instead
//! of `invalid_argument`, and two quoted the objected value unabridged (see
//! [`MAX_DETAIL`]). This crate lies below all three and knows none of them.

#![forbid(unsafe_code)]
// No panic-capable call is permitted on the production path: a panic in a
// codec shared by every internal gRPC caller would take the caller down with
// it. `not(test)` because the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

use std::marker::PhantomData;

use bytes::{Buf as _, BufMut as _};
use tonic::Status;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;

#[must_use]
pub fn server<C>(codec: C) -> tonic::server::Grpc<C>
where
    C: tonic::codec::Codec,
{
    tonic::server::Grpc::new(codec)
        .apply_max_message_size_config(Some(MAX_MESSAGE), Some(MAX_MESSAGE))
}

#[must_use]
pub fn client<T>(inner: T) -> tonic::client::Grpc<T> {
    tonic::client::Grpc::new(inner)
        .max_decoding_message_size(MAX_MESSAGE)
        .max_encoding_message_size(MAX_MESSAGE)
}

pub const MAX_DETAIL: usize = 512;

pub struct JsonCodec<T, U>(PhantomData<(T, U)>);

impl<T, U> Default for JsonCodec<T, U> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T, U> Codec for JsonCodec<T, U>
where
    T: serde::Serialize + Send + 'static,
    U: serde::de::DeserializeOwned + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = JsonEncoder<T>;
    type Decoder = JsonDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        JsonEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        JsonDecoder(PhantomData)
    }
}

pub struct JsonEncoder<T>(PhantomData<T>);

impl<T: serde::Serialize> Encoder for JsonEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        dst.put_slice(&to_bytes(&item)?);
        Ok(())
    }
}

pub struct JsonDecoder<U>(PhantomData<U>);

impl<U: serde::de::DeserializeOwned> Decoder for JsonDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        // `tonic` hands over exactly one complete message; an empty buffer means
        // "nothing there yet", not "empty message".
        if !src.has_remaining() {
            return Ok(None);
        }

        let bytes = src.copy_to_bytes(src.remaining());
        from_bytes(&bytes).map(Some)
    }
}

pub fn to_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(value)
        .map_err(|err| Status::internal(format!("message not encodable: {}", bounded(&err))))
}

pub fn from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(bytes)
        .map_err(|err| Status::invalid_argument(format!("message unreadable: {}", bounded(&err))))
}

fn bounded(err: &serde_json::Error) -> String {
    let text = err.to_string();

    match text.char_indices().nth(MAX_DETAIL) {
        Some((cut, _)) => format!("{} […]", &text[..cut]),
        None => text,
    }
}

#[cfg(test)]
mod limit_tests {
    #[test]
    fn nobody_builds_a_grpc_of_their_own() {
        // Exempt by name, with the reason at the place of the check.
        const EXEMPT: &[&str] = &["tgd/src/identity.rs", "tg-identity/src/control.rs"];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("root");
        let mut findings = Vec::new();
        let mut checked = 0_u32;
        let mut stack = vec![root.join("crates")];

        // An exemption that covers nothing any more is a line nobody touches
        // again.
        for exempt in EXEMPT {
            assert!(
                root.join("crates").join(exempt).exists(),
                "the exemption '{exempt}' points at nothing any more"
            );
        }

        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                // The generated stub, this crate itself — and tests: there the
                // default is sometimes the intent (the witness for the limit
                // needs a path that does **not** have it).
                if name == "pb.rs"
                    || path.starts_with(root.join("crates/tg-wire"))
                    || path.components().any(|part| part.as_os_str() == "tests")
                {
                    continue;
                }
                // The credential port stays at the 4 MiB default: it demands no
                // client certificate, and there the limit is a bound and not a
                // defect.
                if EXEMPT.iter().any(|exempt| path.ends_with(exempt)) {
                    continue;
                }

                let source = std::fs::read_to_string(&path).expect("readable");
                checked += 1;
                if source.contains("server::Grpc::new") || source.contains("client::Grpc::new") {
                    findings.push(path.display().to_string());
                }
            }
        }

        assert!(
            checked > 100,
            "only {checked} source files read — the guard hardly read anything"
        );
        assert!(
            findings.is_empty(),
            "these files build a `Grpc` without the message limit — \
             use `tg_wire::server`/`client`: {findings:?}"
        );
    }
}
