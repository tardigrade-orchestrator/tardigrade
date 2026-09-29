//! The server name from a QUIC Initial (ADR-0092).
//!
//! The egress sidecar decides by the name the connection itself names
//! (ADR-0041). Over TCP it stands in the `ClientHello` of the first record;
//! over QUIC it likewise stands in a `ClientHello`, only that one lies in
//! CRYPTO frames of an **encrypted** Initial packet -- encrypted with keys
//! anyone can derive from the connection ID (RFC 9001 §5.2). That is no
//! confidentiality but protection against middleboxes that freeze the format;
//! for us it is one derivation and one decryption.
//!
//! # What is written by hand here -- and what is not
//!
//! Written by hand is the **frame**: the long header, varints, removing the
//! header protection, AEAD, and the assembly of the CRYPTO frames. The
//! `ClientHello` inside is **not** parsed -- it is wrapped in a TLS record and
//! given to `rustls`, the same seam as with the TLS egress (ADR-0092,
//! determination 3). A hand-written TLS parser would be the kind of code here
//! that one writes wrong once and never notices.
//!
//! # Reassembly is mandatory
//!
//! Today a `ClientHello` often does **not** fit into one Initial:
//! post-quantum key shares burst the 1200 bytes an Initial may carry before
//! the address validation. Whoever reads only the first packet sees nothing
//! for precisely the clients it concerns first (ADR-0092, determination 4).
//!
//! The bytes come from a container. Everything here is therefore bounded: the
//! quantity of assembled CRYPTO bytes, the number of fragments and the number
//! of packets in one datagram.

use std::collections::BTreeMap;

use ring::{aead, hkdf};

const INITIAL_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const VERSION_1: u32 = 0x0000_0001;

const MAX_CID: usize = 20;

const MAX_CRYPTO: usize = 64 * 1024;

const MAX_FRAGMENTS: usize = 256;

const MAX_PACKETS: usize = 4;

const MAX_RECORD: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    Named(String),
    Anonymous,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicError {
    NotInitial,
    UnsupportedVersion(u32),
    Malformed,
    Undecryptable,
    TooMuch,
    NotTls,
}

impl QuicError {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NotInitial => "not_initial",
            Self::UnsupportedVersion(_) => "version",
            Self::Malformed => "malformed",
            Self::Undecryptable => "undecryptable",
            Self::TooMuch => "too_much",
            Self::NotTls => "not_tls",
        }
    }
}

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInitial => write!(f, "no QUIC Initial"),
            Self::UnsupportedVersion(v) => write!(f, "the QUIC version {v:#010x} is not read"),
            Self::Malformed => write!(f, "the QUIC frame is not readable"),
            Self::Undecryptable => write!(f, "the Initial could not be decrypted"),
            Self::TooMuch => write!(f, "the ClientHello bursts the bounds"),
            Self::NotTls => write!(f, "the CRYPTO bytes are no ClientHello"),
        }
    }
}

impl std::error::Error for QuicError {}

#[derive(Debug, Default)]
pub struct Handshake {
    dcid: Option<Vec<u8>>,
    fragments: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
}

impl Handshake {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn absorb(&mut self, datagram: &[u8]) -> Result<Peek, QuicError> {
        let mut rest = datagram;
        let mut seen = 0;

        while !rest.is_empty() && seen < MAX_PACKETS {
            // A datagram often carries several packets in a row
            // (coalesced): Initial, then Handshake. What is no Initial ends
            // the pass -- the length in the header does tell us where the next
            // one begins, but after that nothing comes that we can read.
            let Some(end) = split_initial(rest)? else {
                break;
            };
            let (packet, tail) = rest.split_at(end);
            self.take(packet)?;
            rest = tail;
            seen += 1;
        }

        if self.fragments.is_empty() {
            return Err(QuicError::NotInitial);
        }

        self.peek()
    }

    fn take(&mut self, packet: &[u8]) -> Result<(), QuicError> {
        let header = LongHeader::parse(packet)?;
        let dcid = self.dcid.get_or_insert_with(|| header.dcid.to_vec());
        let payload = decrypt(packet, &header, dcid)?;

        for (offset, data) in crypto_frames(&payload)? {
            if self.fragments.len() >= MAX_FRAGMENTS {
                return Err(QuicError::TooMuch);
            }
            self.bytes = self.bytes.saturating_add(data.len());
            if self.bytes > MAX_CRYPTO {
                return Err(QuicError::TooMuch);
            }
            self.fragments.insert(offset, data);
        }

        Ok(())
    }

    fn contiguous(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        for (&offset, data) in &self.fragments {
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            if offset > out.len() {
                break;
            }
            // A fragment may overlap one that is already there; the part
            // behind it is taken. Whoever sends the same thing twice shifts
            // nothing by it.
            if let Some(fresh) = data.get(out.len() - offset..) {
                out.extend_from_slice(fresh);
            }
        }

        out
    }

    fn peek(&self) -> Result<Peek, QuicError> {
        let bytes = self.contiguous();

        // The handshake head is four bytes: type and 24-bit length. Without
        // it not even how much is still missing is known.
        let Some(head) = bytes.get(..4) else {
            return Ok(Peek::Incomplete);
        };
        if head[0] != 0x01 {
            return Err(QuicError::NotTls);
        }
        let want = 4
            + ((u32::from(head[1]) << 16) | (u32::from(head[2]) << 8) | u32::from(head[3]))
                as usize;
        if bytes.len() < want {
            return Ok(Peek::Incomplete);
        }

        read_client_hello(&bytes[..want])
    }
}

fn read_client_hello(handshake: &[u8]) -> Result<Peek, QuicError> {
    let mut acceptor = rustls::server::Acceptor::default();

    for chunk in handshake.chunks(MAX_RECORD) {
        let len = u16::try_from(chunk.len()).map_err(|_| QuicError::TooMuch)?;
        let mut record = Vec::with_capacity(chunk.len() + 5);
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(chunk);

        let mut cursor = std::io::Cursor::new(&record[..]);
        while cursor.position() < record.len() as u64 {
            acceptor
                .read_tls(&mut cursor)
                .map_err(|_| QuicError::NotTls)?;
        }
    }

    match acceptor.accept() {
        Ok(Some(accepted)) => Ok(accepted
            .client_hello()
            .server_name()
            .map_or(Peek::Anonymous, |name| Peek::Named(name.to_owned()))),
        Ok(None) => Ok(Peek::Incomplete),
        Err(_) => Err(QuicError::NotTls),
    }
}

struct LongHeader<'a> {
    dcid: &'a [u8],
    number_at: usize,
    end: usize,
}

impl<'a> LongHeader<'a> {
    fn parse(packet: &'a [u8]) -> Result<Self, QuicError> {
        let mut r = Reader::new(packet);
        let first = r.byte()?;

        // Header form 1, fixed bit 1, type 00 = Initial.
        if first & 0xf0 != 0xc0 {
            return Err(QuicError::NotInitial);
        }
        let version = r.u32()?;
        if version != VERSION_1 {
            return Err(QuicError::UnsupportedVersion(version));
        }

        let dcid = r.cid()?;
        let _scid = r.cid()?;
        let token = usize::try_from(r.varint()?).map_err(|_| QuicError::Malformed)?;
        r.skip(token)?;

        let length = usize::try_from(r.varint()?).map_err(|_| QuicError::Malformed)?;
        let number_at = r.at;
        let end = number_at.checked_add(length).ok_or(QuicError::Malformed)?;
        if end > packet.len() {
            return Err(QuicError::Malformed);
        }

        Ok(Self {
            dcid,
            number_at,
            end,
        })
    }
}

fn split_initial(datagram: &[u8]) -> Result<Option<usize>, QuicError> {
    match LongHeader::parse(datagram) {
        Ok(header) => Ok(Some(header.end)),
        Err(QuicError::NotInitial) => Ok(None),
        Err(other) => Err(other),
    }
}

fn decrypt(packet: &[u8], header: &LongHeader<'_>, dcid: &[u8]) -> Result<Vec<u8>, QuicError> {
    let (key, iv, hp) = initial_keys(dcid).ok_or(QuicError::Undecryptable)?;

    // The sample lies four bytes behind the beginning of the packet number
    // -- the number is at most four bytes long, so the offset covers every
    // length without knowing it (RFC 9001 §5.4.2).
    let from = header.number_at + 4;
    let sample = packet.get(from..from + 16).ok_or(QuicError::Malformed)?;

    let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp)
        .map_err(|_| QuicError::Undecryptable)?;
    let mask = hp.new_mask(sample).map_err(|_| QuicError::Undecryptable)?;

    // `packet[0]` is safe here, and the guarantee stands four lines above:
    // the `?` on `sample` succeeds only if the packet has `from + 16` bytes.
    let first = packet[0] ^ (mask[0] & 0x0f);
    // `& 0x03` makes the length `1..=4` (RFC 9000, section 17.2) -- so
    // `mask[i + 1]` lies in `1..=4` below, and the mask is a `[u8; 5]`.
    // Without this masking the loop would run past it.
    let number_len = usize::from(first & 0x03) + 1;
    debug_assert!((1..=4).contains(&number_len));

    let mut number = 0_u64;
    let mut bytes = Vec::with_capacity(number_len);
    for i in 0..number_len {
        let byte = packet
            .get(header.number_at + i)
            .ok_or(QuicError::Malformed)?
            ^ mask[i + 1];
        number = (number << 8) | u64::from(byte);
        bytes.push(byte);
    }

    // The associated data are the header **including** the packet number,
    // and unprotected at that (RFC 9001 §5.3). Cutting them off yields an AAD
    // that never fits -- and the error showed up as a decryption that fails on
    // principle.
    let end = header.number_at + number_len;
    let mut aad = packet.get(..end).ok_or(QuicError::Malformed)?.to_vec();
    aad[0] = first;
    let slot = aad
        .get_mut(header.number_at..)
        .ok_or(QuicError::Malformed)?;
    if slot.len() != bytes.len() {
        return Err(QuicError::Malformed);
    }
    slot.copy_from_slice(&bytes);

    let mut nonce = iv;
    for (slot, byte) in nonce
        .iter_mut()
        .rev()
        .zip(number.to_be_bytes().iter().rev())
    {
        *slot ^= *byte;
    }

    let mut payload = packet
        .get(end..header.end)
        .ok_or(QuicError::Malformed)?
        .to_vec();

    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| QuicError::Undecryptable)?,
    );
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut payload,
        )
        .map_err(|_| QuicError::Undecryptable)?;

    Ok(plain.to_vec())
}

fn initial_keys(dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, INITIAL_SALT_V1).extract(dcid);
    let client = expand_label(&initial, b"client in", 32)?;
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);

    let mut key = [0_u8; 16];
    let mut iv = [0_u8; 12];
    let mut hp = [0_u8; 16];
    key.copy_from_slice(&expand_label(&prk, b"quic key", 16)?);
    iv.copy_from_slice(&expand_label(&prk, b"quic iv", 12)?);
    hp.copy_from_slice(&expand_label(&prk, b"quic hp", 16)?);

    Some((key, iv, hp))
}

fn expand_label(prk: &hkdf::Prk, label: &[u8], out: u16) -> Option<Vec<u8>> {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&out.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);

    let out = usize::from(out);
    let mut bytes = vec![0_u8; out];
    prk.expand(&[&info], Len(out)).ok()?.fill(&mut bytes).ok()?;

    Some(bytes)
}

fn crypto_frames(payload: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, QuicError> {
    let mut r = Reader::new(payload);
    let mut out = Vec::new();

    while r.at < payload.len() {
        match r.varint()? {
            // PADDING and PING carry nothing.
            0x00 | 0x01 => {}
            // ACK -- the two forms carry the same fields, `0x03`
            // additionally three ECN counters.
            kind @ (0x02 | 0x03) => {
                let _largest = r.varint()?;
                let _delay = r.varint()?;
                let ranges = r.varint()?;
                let _first = r.varint()?;
                for _ in 0..ranges.min(u64::try_from(payload.len()).unwrap_or(u64::MAX)) {
                    let _gap = r.varint()?;
                    let _len = r.varint()?;
                }
                if kind == 0x03 {
                    let _ = (r.varint()?, r.varint()?, r.varint()?);
                }
            }
            0x06 => {
                let offset = r.varint()?;
                let len = usize::try_from(r.varint()?).map_err(|_| QuicError::Malformed)?;
                out.push((offset, r.take(len)?.to_vec()));
            }
            // CONNECTION_CLOSE with an error code from the transport.
            0x1c => {
                let _code = r.varint()?;
                let _frame = r.varint()?;
                let len = usize::try_from(r.varint()?).map_err(|_| QuicError::Malformed)?;
                r.skip(len)?;
            }
            _ => break,
        }
    }

    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, QuicError> {
        let byte = *self.bytes.get(self.at).ok_or(QuicError::Malformed)?;
        self.at += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, QuicError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| QuicError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], QuicError> {
        let end = self.at.checked_add(len).ok_or(QuicError::Malformed)?;
        let slice = self.bytes.get(self.at..end).ok_or(QuicError::Malformed)?;
        self.at = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), QuicError> {
        self.take(len).map(|_| ())
    }

    fn cid(&mut self) -> Result<&'a [u8], QuicError> {
        let len = usize::from(self.byte()?);
        if len > MAX_CID {
            return Err(QuicError::Malformed);
        }
        self.take(len)
    }

    fn varint(&mut self) -> Result<u64, QuicError> {
        let first = self.byte()?;
        let extra = usize::from(first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take((1 << extra) - 1)? {
            value = (value << 8) | u64::from(*byte);
        }

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Handshake, MAX_CRYPTO, MAX_FRAGMENTS, Peek, QuicError, aead, initial_keys};

    fn crypto(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06];
        out.extend(varint(offset));
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![u8::try_from(value).expect("below 64")]
        } else if value < 16_384 {
            (0x4000 | u16::try_from(value).expect("below 2^14"))
                .to_be_bytes()
                .to_vec()
        } else {
            (0x8000_0000 | u32::try_from(value).expect("below 2^30"))
                .to_be_bytes()
                .to_vec()
        }
    }

    fn sealed(dcid: &[u8], payload: &[u8]) -> Vec<u8> {
        let (key, iv, hp) = initial_keys(dcid).expect("the Initial keys");

        // Type byte: header form, fixed, type Initial, packet number one byte.
        let mut header = vec![0xC0];
        header.extend(1_u32.to_be_bytes());
        header.push(u8::try_from(dcid.len()).expect("a short identifier"));
        header.extend_from_slice(dcid);
        header.push(0x00); // the source identifier is empty
        header.push(0x00); // the token length
        header.extend(varint(1 + payload.len() as u64 + 16));
        let number_at = header.len();
        header.push(0x00); // packet number 0 -- so the nonce is the IV

        let sealing = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &key).expect("the key"),
        );
        let mut sealed = payload.to_vec();
        sealing
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(&header),
                &mut sealed,
            )
            .expect("seal");

        let mut packet = header;
        packet.extend_from_slice(&sealed);

        // Header protection last: the sample lies in the sealed payload
        // (RFC 9001 §5.4.2).
        let from = number_at + 4;
        let sample = &packet[from..from + 16];
        let hpk =
            aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp).expect("the HP key");
        let mask = hpk.new_mask(sample).expect("the mask");
        packet[0] ^= mask[0] & 0x0f;
        packet[number_at] ^= mask[1];

        packet
    }

    #[test]
    fn the_sealer_produces_a_packet_the_reader_accepts() {
        let dcid = [0xAB_u8; 8];
        // A fragment that does not complete the ClientHello: the reader
        // takes it in and reports `Incomplete`.
        let packet = sealed(&dcid, &crypto(0, &[0x01, 0x02, 0x03]));

        assert_eq!(
            Handshake::new().absorb(&packet),
            Ok(Peek::Incomplete),
            "the reader must accept the built packet"
        );
    }

    #[test]
    fn two_hundred_fifty_seven_fragments_are_too_many() {
        let dcid = [0xCD_u8; 8];

        let mut payload = Vec::new();
        for offset in 0..257_u64 {
            payload.extend(crypto(offset, &[0x00]));
        }
        assert!(
            payload.len() < MAX_CRYPTO,
            "the byte bound must not bite here, otherwise the witness checks \
             the other bound: {} bytes",
            payload.len()
        );

        assert_eq!(
            Handshake::new().absorb(&sealed(&dcid, &payload)),
            Err(QuicError::TooMuch),
            "{MAX_FRAGMENTS} fragments are the bound"
        );
    }

    #[test]
    fn two_hundred_fifty_six_fragments_are_accepted() {
        let dcid = [0xCD_u8; 8];

        let mut payload = Vec::new();
        for offset in 0..256_u64 {
            payload.extend(crypto(offset, &[0x00]));
        }

        // **`NotTls` is the stronger statement here than `Incomplete`.** The
        // 256 one-byte fragments lie without gaps from offset 0, so they are
        // taken in **and** assembled -- and fail only at the interpretation,
        // because 256 zero bytes are no `ClientHello`. A `TooMuch` would mean
        // that the bound bites already at 256.
        assert_eq!(
            Handshake::new().absorb(&sealed(&dcid, &payload)),
            Err(QuicError::NotTls),
            "exactly {MAX_FRAGMENTS} must be taken in"
        );
    }
}
