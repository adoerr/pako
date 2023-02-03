#![allow(dead_code)]

use nom::{bytes::complete::take, error::ParseError, number::complete::be_u32, IResult};

// The writing application writes `0x1A2B3C4D` with it's native byte ordering
// format into the byte order magic field. The reading application will read
// either `0x1A2B3C4D` (identical) or `0x4D3C2B1A` (swapped). If the reading
// application reads the swapped value, it knows that all the following fields
// will have to be swapped too.
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// The block type uniquely identifies a block.
#[repr(u32)]
#[derive(Debug)]
pub enum BlockType {
    SectionHeader = 0x0A0D_0D0A,
}

/// The Section Header Block (SHB) is mandatory. It identifies the beginning of
/// a section of the capture file. The Section Header Block does not contain
/// data but it rather identifies a list of blocks (interfaces, packets) that
/// are logically correlated.
#[derive(Debug)]
pub struct SectionHeader<'a> {
    pub block_type: BlockType,
    pub total_length: u32,
    pub byte_order: u32,
    pub major: u16,
    pub minor: u16,
    pub section_length: i64,
    pub options: &'a [u8],
    pub total_length_dup: u32,
}

pub fn section_header<'a, E>(input: &'a [u8]) -> IResult<&'a [u8], u32, E>
where
    E: ParseError<&'a [u8]>,
{
    let (input, _) = take(8usize)(input)?;
    let (input, byte_order) = be_u32(input)?;

    Ok((input, byte_order))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use nom::error::VerboseError;

    use crate::block::{section_header, BYTE_ORDER_MAGIC};

    #[test]
    fn byte_order_be_works() -> Result<()> {
        let pcap = include_bytes!("../assets/test002_be.pcapng");
        let (_, byte_order) = section_header::<VerboseError<&[u8]>>(pcap)?;
        assert_eq!(BYTE_ORDER_MAGIC, byte_order);
        Ok(())
    }

    #[test]
    fn byte_order_le_fails() -> Result<()> {
        let pcap = include_bytes!("../assets/test002_le.pcapng");
        let (_, byte_order) = section_header::<VerboseError<&[u8]>>(pcap)?;
        assert_ne!(BYTE_ORDER_MAGIC, byte_order);
        Ok(())
    }
}
