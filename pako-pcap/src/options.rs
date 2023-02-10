#![allow(dead_code)]

/// Code that specifies the type of the current TLV record
#[repr(u16)]
#[derive(Debug)]
pub enum Code {
    EndOfOpt = 0,
    Comment = 1,
    Custom2988 = 2988,
    Custom2989 = 2989,
    Custom19372 = 19372,
    Custom19373 = 19373,
}

/// All the block bodies MAY embed optional fields. Optional fields can be used
/// to insert some information that may be useful when reading data, but that
/// is not really needed for packet processing.
#[derive(Debug)]
pub struct Option<'a> {
    pub code: Code,
    pub len: u16,
    pub value: &'a [u8],
}
