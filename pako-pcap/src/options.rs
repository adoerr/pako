#![allow(dead_code)]

/// Align input value to 32-bit boundary
#[macro_export]
macro_rules! align32 {
    ($val:expr) => {
        ($val + 3) & !($val - 1)
    };
}

/// Code that specifies the type of the current TLV record
#[repr(u16)]
#[derive(Debug)]
pub enum Code {
    EndOfOpt = 0,
    Comment = 1,
    Hardware = 2,
    OS = 3,
    UserAppl = 4,
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
        assert_eq!(align32!(3), 4);
        assert_eq!(align32!(4), 4);
        assert_eq!(align32!(5), 8);
        assert_eq!(align32!(5u32), 8);
        assert_eq!(align32!(5i32), 8);
        assert_eq!(align32!(5usize), 8);
    }
}
