use nom::{error::ParseError, IResult};

pub enum BigEndian {}

/// System native endianness
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

pub enum LittleEndian {}

/// System native endianness
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;

/// Network byte order
pub type NetworkEndian = BigEndian;

/// [`ByteOrder`] can deserialize integers from bytes
pub(crate) trait ByteOrder {
    fn parse_u16<'a, E: ParseError<&'a [u8]>>(input: &'a [u8]) -> IResult<&'a [u8], u16, E>;
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(input: &'a [u8]) -> IResult<&'a [u8], u32, E>;
}
