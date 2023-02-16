#![allow(dead_code)]

use nom::{error::ParseError, IResult};

use crate::Error;

/// Align input value to 32-bit boundary
#[macro_export]
macro_rules! align32 {
    ($val:expr) => {
        ($val + 3) & !($val - 1)
    };
}

/// Code that specifies the type of the current TLV record
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
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

impl TryFrom<u16> for Code {
    type Error = Error<&'static [u8]>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Code::EndOfOpt),
            1 => Ok(Code::Comment),
            2 => Ok(Code::Hardware),
            3 => Ok(Code::OS),
            4 => Ok(Code::UserAppl),
            2988 => Ok(Code::Custom2988),
            2989 => Ok(Code::Custom2989),
            19372 => Ok(Code::Custom19372),
            19373 => Ok(Code::Custom19373),
            _ => Err(Error::Option(value)),
        }
    }
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

/// Parse an [`Option`}
pub(crate) fn option<'a, E>(_input: &'a [u8]) -> IResult<&'a [u8], Option, E>
where
    E: ParseError<&'a [u8]>,
{
    todo!()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{options::Code, Error};

    #[test]
    fn align_works() {
        assert_eq!(align32!(3), 4);
        assert_eq!(align32!(4), 4);
        assert_eq!(align32!(5), 8);
        assert_eq!(align32!(5u32), 8);
        assert_eq!(align32!(5i32), 8);
        assert_eq!(align32!(5usize), 8);
    }

    #[test]
    fn code_try_from_works() -> Result<()> {
        assert_eq!(Code::try_from(0).unwrap(), Code::EndOfOpt);
        assert_eq!(Code::try_from(1).unwrap(), Code::Comment);
        assert_eq!(Code::try_from(2).unwrap(), Code::Hardware);
        assert_eq!(Code::try_from(3).unwrap(), Code::OS);
        assert_eq!(Code::try_from(4).unwrap(), Code::UserAppl);
        assert_eq!(Code::try_from(2988).unwrap(), Code::Custom2988);
        assert_eq!(Code::try_from(2989).unwrap(), Code::Custom2989);
        assert_eq!(Code::try_from(19372).unwrap(), Code::Custom19372);
        assert_eq!(Code::try_from(19373).unwrap(), Code::Custom19373);

        Ok(())
    }

    #[test]
    fn code_try_from_fails() {
        assert!(matches!(Code::try_from(42), Err(Error::Option(42))));
        assert!(matches!(Code::try_from(5), Err(Error::Option(5))));
        assert!(matches!(Code::try_from(2990), Err(Error::Option(2990))));
        assert!(matches!(Code::try_from(19374), Err(Error::Option(19374))));
    }
}
