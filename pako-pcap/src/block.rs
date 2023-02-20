//!
//! General Block Structure support
//!

/// The block type uniquely identifies a block.
#[repr(u32)]
#[derive(Debug)]
pub enum BlockType {
    SectionHeader = 0x0A0D_0D0A,
}
