//!
//! General Block Structure support
//!
//! A capture file is organized in blocks, that are appended one to another
//! to form the file. All the blocks share a common format,
//!
//!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  0 |                          Block Type                           |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  4 |                      Block Total Length                       |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  8 /                          Block Body                           /
//!    /              variable length, padded to 32 bits               /
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |                      Block Total Length                       |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use nom::IResult;

/// The block type uniquely identifies a block.
#[repr(u32)]
#[derive(Debug)]
pub enum BlockType {
    SectionHeader = 0x0A0D_0D0A,
    InterfaceDescription = 0x0000_0001,
    SimplePacket = 0x0000_0003,
    NameResolution = 0x0000_0004,
    InterfaceStatistic = 0x0000_0005,
    EnhancedPacket = 0x0000_0006,
    SystemJournalExport = 0x0000_0009,
    DecryptionSecretsBlock = 0x0000_000A,
    Custom = 0x0000_0BAD,
}

/// [`BlockParser`] is implemented by each block type in order to parse the
/// block type specific block body
trait BlockParser<O> {
    /// Block header size
    const HEADER_SIZE: usize;

    /// Block type identifier
    const BLOCK_TYPE: BlockType;

    /// Block body parser
    fn parse_body<E>(
        blk_type: BlockType,
        blk_len1: u32,
        blk_body: &[u8],
        blk_len2: u32,
    ) -> IResult<&[u8], O, E>;
}
