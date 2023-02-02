#![allow(dead_code)]

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
