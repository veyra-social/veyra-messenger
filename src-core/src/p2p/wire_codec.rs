//! A size-bounded CBOR codec for the request/response protocols.
//!
//! The wire limits declared next to the protocol structs used to be constants
//! and nothing else: every protocol ran on `request_response::cbor::Behaviour`,
//! whose codec carries the library's own defaults (1 MiB request, 10 MiB
//! response) and is not constructible from outside the crate, so our numbers
//! could not be applied even in principle. A constant that looks like a limit
//! but is not one is worse than no constant (code review 2026-07-27).
//!
//! The encoding is byte-for-byte what the library codec produces — the same
//! `cbor4ii::serde` call — so this is not a wire change. The difference is on
//! the read side: the library truncates at its maximum and lets the CBOR
//! decode fail somewhere downstream, while this codec reads one byte past the
//! limit and reports the overrun as what it is.

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::marker::PhantomData;

/// CBOR codec with explicit per-protocol request and response limits.
pub struct BoundedCborCodec<Req, Resp> {
    request_max: u64,
    response_max: u64,
    phantom: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> BoundedCborCodec<Req, Resp> {
    pub fn new(request_max: usize, response_max: usize) -> Self {
        Self {
            request_max: request_max as u64,
            response_max: response_max as u64,
            phantom: PhantomData,
        }
    }
}

impl<Req, Resp> Clone for BoundedCborCodec<Req, Resp> {
    fn clone(&self) -> Self {
        Self {
            request_max: self.request_max,
            response_max: self.response_max,
            phantom: PhantomData,
        }
    }
}

async fn read_bounded<T>(io_stream: &mut T, max: u64, what: &'static str) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buffer = Vec::new();
    // One byte past the limit: reading exactly `max` cannot tell a payload
    // that fits from one that was cut off at the boundary.
    io_stream
        .take(max.saturating_add(1))
        .read_to_end(&mut buffer)
        .await?;
    if buffer.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} exceeds the {max}-byte protocol limit"),
        ));
    }
    Ok(buffer)
}

#[async_trait]
impl<Req, Resp> request_response::Codec for BoundedCborCodec<Req, Resp>
where
    Req: Send + Serialize + DeserializeOwned,
    Resp: Send + Serialize + DeserializeOwned,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io_stream: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded(io_stream, self.request_max, "request").await?;
        cbor4ii::serde::from_slice(bytes.as_slice()).map_err(decode_error)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io_stream: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded(io_stream, self.response_max, "response").await?;
        cbor4ii::serde::from_slice(bytes.as_slice()).map_err(decode_error)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io_stream: &mut T,
        request: Req,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes: Vec<u8> = cbor4ii::serde::to_vec(Vec::new(), &request).map_err(encode_error)?;
        io_stream.write_all(&bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io_stream: &mut T,
        response: Resp,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes: Vec<u8> = cbor4ii::serde::to_vec(Vec::new(), &response).map_err(encode_error)?;
        io_stream.write_all(&bytes).await
    }
}

fn decode_error<E: std::fmt::Debug>(err: cbor4ii::serde::DecodeError<E>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cbor decode failed: {err:?}"),
    )
}

fn encode_error<E: std::fmt::Debug>(err: cbor4ii::serde::EncodeError<E>) -> io::Error {
    io::Error::other(format!("cbor encode failed: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec as _;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Payload {
        blob: String,
    }

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/veyra/test/1.0.0")
    }

    /// Encodes a payload whose CBOR length is exactly `target` bytes.
    fn payload_of_encoded_len(target: usize) -> Vec<u8> {
        let mut blob_len = target;
        loop {
            let encoded: Vec<u8> = cbor4ii::serde::to_vec(
                Vec::new(),
                &Payload {
                    blob: "x".repeat(blob_len),
                },
            )
            .unwrap();
            match encoded.len().cmp(&target) {
                std::cmp::Ordering::Equal => return encoded,
                std::cmp::Ordering::Greater => blob_len -= 1,
                std::cmp::Ordering::Less => blob_len += 1,
            }
        }
    }

    /// The three cases that matter for a limit: just under, exactly on, and
    /// one byte over.
    #[test]
    fn request_limit_admits_up_to_the_boundary_and_no_further() {
        const LIMIT: usize = 512;
        let mut codec = BoundedCborCodec::<Payload, Payload>::new(LIMIT, LIMIT);
        for len in [LIMIT - 1, LIMIT] {
            let bytes = payload_of_encoded_len(len);
            let decoded = futures::executor::block_on(
                codec.read_request(&protocol(), &mut futures::io::Cursor::new(bytes)),
            );
            assert!(decoded.is_ok(), "a {len}-byte request was rejected");
        }
        let over = payload_of_encoded_len(LIMIT + 1);
        let err = futures::executor::block_on(
            codec.read_request(&protocol(), &mut futures::io::Cursor::new(over)),
        )
        .expect_err("a request past the limit was accepted");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn response_limit_is_separate_from_the_request_limit() {
        let mut codec = BoundedCborCodec::<Payload, Payload>::new(4096, 256);
        let body = payload_of_encoded_len(1024);
        // Fits the request limit...
        assert!(futures::executor::block_on(
            codec.read_request(&protocol(), &mut futures::io::Cursor::new(body.clone()))
        )
        .is_ok());
        // ...and is far past the response limit.
        assert!(futures::executor::block_on(
            codec.read_response(&protocol(), &mut futures::io::Cursor::new(body))
        )
        .is_err());
    }

    #[test]
    fn round_trip_matches_the_library_encoding() {
        let mut codec = BoundedCborCodec::<Payload, Payload>::new(4096, 4096);
        let payload = Payload {
            blob: "hello".to_string(),
        };
        let mut wire = Vec::new();
        futures::executor::block_on(codec.write_request(&protocol(), &mut wire, payload.clone()))
            .unwrap();
        // Byte-for-byte what `cbor::Behaviour` would have written.
        let expected: Vec<u8> = cbor4ii::serde::to_vec(Vec::new(), &payload).unwrap();
        assert_eq!(wire, expected);
        let decoded = futures::executor::block_on(
            codec.read_request(&protocol(), &mut futures::io::Cursor::new(wire)),
        )
        .unwrap();
        assert_eq!(decoded, payload);
    }
}
