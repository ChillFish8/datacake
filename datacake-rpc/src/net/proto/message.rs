use std::io;
use std::io::ErrorKind;
use bytes::{Buf, BytesMut};
use rkyv::AlignedVec;
use tokio_util::codec::Decoder;


#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// The frame type identifier.
pub enum FrameType {
    /// Hidden frame type not sent.
    Unknown = 0,
    /// A header frame containing information about the upcoming frames.
    Header = 1,
    /// A single message payload which can be deserialized.
    Message = 2,
    /// A ping frame used to prevent timeouts.
    Ping = 3,
}

impl TryFrom<u8> for FrameType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(FrameType::Header),
            2 => Ok(FrameType::Message),
            3 => Ok(FrameType::Ping),
            _ => Err(io::Error::new(ErrorKind::InvalidData, "Invalid frame type provided")),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// A metadata header frame which comes before the actual message
/// payloads.
///
/// This header allows the service to route and validate requests
pub struct HeaderFrame {
    /// The ID of the route the messages are destined for.
    ///
    /// This effectively acts like the URL of the framework, the ID itself
    /// should be a stable u64 hash derived by the city hasher system.
    pub route_id: u64,
    /// Signals if more than one message is expected to be received from the stream.
    pub is_message_stream: bool,
}

impl HeaderFrame {
    /// The size of the encoded frame in bytes.
    const FRAME_SIZE: usize = 9;

    fn to_bytes(self) -> [u8; Self::FRAME_SIZE] {
        let mut buf = [0; Self::FRAME_SIZE];
        buf[0..8].copy_from_slice(&self.route_id.to_le_bytes());
        buf[8] = self.is_message_stream as u8;
        buf
    }
}


#[derive(Debug)]
/// A wrapper enum around the possible frames being sent or received.
pub enum Frame {
    /// The header frame.
    Header(HeaderFrame),
    /// A single message buffer chunk.
    ///
    /// This contains an aligned buffer which has been pre-validated.
    Message(AlignedVec),
    /// A simple ping frame to reset the servers internal timeouts.
    Ping,
}


/// A wrapped frame that implements the required tokio codec.
pub struct FrameDecoder {
    expect_frame: FrameType,
    expect_len: usize,
}

impl FrameDecoder {
    /// Creates a new decode.
    pub fn new() -> Self {
        Self {
            expect_frame: FrameType::Unknown,
            expect_len: 0,
        }
    }

    fn reset_decoder(&mut self) {
        self.expect_frame = FrameType::Unknown;
        self.expect_len = 0;
    }
}

impl Decoder for FrameDecoder {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.expect_frame == FrameType::Unknown {
            if src.is_empty() {
                return Ok(None)
            }

            self.expect_frame = FrameType::try_from(src.get_u8())?;
        }

        match self.expect_frame {
            FrameType::Ping => {
                self.reset_decoder();
                Ok(Some(Frame::Ping))
            },
            FrameType::Header => {
                if src.len() < HeaderFrame::FRAME_SIZE {
                    return Ok(None)
                }

                let route_id = src.get_u64_le();
                let is_stream = src.get_u8();

                let header = HeaderFrame {
                    route_id,
                    is_message_stream: is_stream == 1,
                };

                self.reset_decoder();
                Ok(Some(Frame::Header(header)))
            },
            FrameType::Message => {
                if self.expect_len == 0  {
                    if src.len() < 4 {
                        return Ok(None)
                    }

                    self.expect_len = src.get_u32_le() as usize;
                }

                if src.len() < self.expect_len {
                    return Ok(None);
                }

                let mut aligned = AlignedVec::with_capacity(self.expect_len);
                aligned.extend_from_slice(&src[..self.expect_len]);

                Ok(Some(Frame::Message(aligned)))
            },
            FrameType::Unknown => {
                self.reset_decoder();
                Ok(None)
            },
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn ping_frame() -> Vec<u8> {
        vec![
            FrameType::Ping as u8,
        ]
    }

    fn header_frame() -> Vec<u8> {
        let header = HeaderFrame {
            route_id: 12345,
            is_message_stream: true,
        };

        let mut frame = Vec::new();
        frame.push(FrameType::Header as u8);
        frame.extend_from_slice(&header.to_bytes());
        frame
    }

    fn message_frame() -> Vec<u8> {
        let content = b"Hello, world!".as_slice();
        let len = content.len();

        let mut frame = Vec::new();
        frame.push(FrameType::Message as u8);
        frame.extend_from_slice(&(len as u32).to_le_bytes());
        frame.extend_from_slice(content);
        frame
    }

    #[test]
    fn test_frame_decode_ping() {
        let mut decoder = FrameDecoder::new();

        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&ping_frame());

        let frame = decoder.decode(&mut buffer).expect("Decode OK");
        assert!(matches!(frame, Some(Frame::Ping)));
    }

    #[test]
    fn test_frame_decode_header() {
        let mut decoder = FrameDecoder::new();

        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&header_frame());

        let frame = decoder.decode(&mut buffer).expect("Decode OK");

        if let Some(Frame::Header(frame)) = frame {
            assert!(frame.is_message_stream);
            assert_eq!(frame.route_id, 12345);
        } else {
            panic!("Expected header frame, got {:?}", frame);
        }
    }

    #[test]
    fn test_frame_decode_message() {
        let mut decoder = FrameDecoder::new();

        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&message_frame());

        let frame = decoder.decode(&mut buffer).expect("Decode OK");

        if let Some(Frame::Message(content)) = frame {
            assert_eq!(content.as_slice(), b"Hello, world!");
        } else {
            panic!("Expected message frame, got {:?}", frame);
        }
    }

    #[test]
    fn test_frame_invalid() {
        let mut decoder = FrameDecoder::new();

        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&[0, 234, 29, 3, 9]);

        let error = decoder.decode(&mut buffer)
            .expect_err("Decode should error");
        assert_eq!(error.kind(), ErrorKind::InvalidData, "Decoder should return invalid data");
    }
}
