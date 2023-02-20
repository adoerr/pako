//!
//! Section Header Block (SHB) support
//!

use nom::{
    error::ParseError,
    number::complete::{be_i64, be_u16, be_u32},
    IResult,
};

use crate::BlockType;

// The writing application writes `0x1A2B3C4D` with it's native byte ordering
// format into the byte order magic field. The reading application will read
// either `0x1A2B3C4D` (identical) or `0x4D3C2B1A` (swapped). If the reading
// application reads the swapped value, it knows that all the following fields
// will have to be swapped too.
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

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
    pub options: Option<&'a [u8]>,
    pub total_length_dup: u32,
}

pub fn section_header<'a, E>(input: &'a [u8]) -> IResult<&'a [u8], SectionHeader, E>
where
    E: ParseError<&'a [u8]>,
{
    let (input, _) = be_u32(input)?;
    let (input, total_length) = be_u32(input)?;
    let (input, byte_order) = be_u32(input)?;
    let (input, major) = be_u16(input)?;
    let (input, minor) = be_u16(input)?;
    let (input, section_length) = be_i64(input)?;

    Ok((
        input,
        SectionHeader {
            block_type: BlockType::SectionHeader,
            total_length,
            byte_order,
            major,
            minor,
            section_length,
            options: None,
            total_length_dup: total_length,
        },
    ))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use nom::error::VerboseError;

    use crate::section_header::{section_header, BYTE_ORDER_MAGIC};

    #[test]
    fn byte_order_be_works() -> Result<()> {
        let pcap = include_bytes!("../assets/test002_be.pcapng");
        let (_, shb) = section_header::<VerboseError<&[u8]>>(pcap)?;
        assert_eq!(BYTE_ORDER_MAGIC, shb.byte_order);
        Ok(())
    }

    #[test]
    fn byte_order_le_fails() -> Result<()> {
        let pcap = include_bytes!("../assets/test002_le.pcapng");
        let (_, shb) = section_header::<VerboseError<&[u8]>>(pcap)?;
        assert_ne!(BYTE_ORDER_MAGIC, shb.byte_order);
        Ok(())
    }

    #[test]
    /// TODO: complete this test
    fn section_header_works() -> Result<()> {
        let pcap = include_bytes!("../assets/test002_be.pcapng");
        let (_, shb) = section_header::<VerboseError<&[u8]>>(pcap)?;

        assert_eq!(96, shb.total_length);
        assert_eq!(-1, shb.section_length);

        Ok(())
    }
}
