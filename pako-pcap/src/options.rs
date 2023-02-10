#![allow(dead_code)]

/// Align input value to the next multiple of n bytes, where n is a power of two.
#[macro_export]
macro_rules! align {
    ($val:expr, $n:expr) => {
        ($val + ($n - 1)) & !($val - 1)
    };
}

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

#[cfg(test)]
mod tests {
    #[test]
    fn align_works() {
        assert_eq!(align!(3, 4), 4);
        assert_eq!(align!(4, 4), 4);
        assert_eq!(align!(5, 4), 8);
        assert_eq!(align!(5u32, 4), 8);
        assert_eq!(align!(5i32, 4), 8);
        assert_eq!(align!(5usize, 4), 8);
    }
}
