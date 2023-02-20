//!
//! Optional fields support
//!

use nom::{bytes::complete::take, number::complete::be_u16, IResult};

use crate::Error;

/// Align input value `val` to a power of 2 alignment `align`
#[macro_export]
macro_rules! align {
    ($val:expr, $align:expr) => {
        ($val + ($align - 1)) & !($align - 1)
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
pub(crate) fn option(input: &[u8]) -> IResult<&[u8], Option, Error<&[u8]>> {
    let (input, code) = be_u16(input)?;
    let (input, len) = be_u16(input)?;
    let (input, value) = take(align!(len, 4))(input)?;

    Ok((
        input,
        Option {
            code: Code::try_from(code).map_err(nom::Err::Error)?,
            len,
            value,
        },
    ))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{
        options::{option, Code},
        Error,
    };

    #[test]
    fn align_works() {
        assert_eq!(align!(3, 4), 4);
        assert_eq!(align!(4, 4), 4);
        assert_eq!(align!(5, 4), 8);
        assert_eq!(align!(9, 4), 12);
        assert_eq!(align!(5u32, 4), 8);
        assert_eq!(align!(5i32, 4), 8);
        assert_eq!(align!(5usize, 4), 8);
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

    #[test]
    fn option_works() -> Result<()> {
        #[rustfmt::skip]
        let tests = [
            (vec![0x00, 0x02, 0x00, 0x09, 0x41, 0x70, 0x70, 0x6C, 0x65, 0x20, 0x4D, 0x42, 0x50, 0x00, 0x00, 0x00], (Code::Hardware, 9, "Apple MBP")),
            (vec![0x00, 0x03, 0x00, 0x0C, 0x4F, 0x53, 0x2D, 0x58, 0x20, 0x31, 0x30, 0x2E, 0x31, 0x30, 0x2E, 0x35], (Code::OS, 12, "OS-X 10.10.5")),
            (vec![0x00, 0x04, 0x00, 0x0F, 0x70, 0x63, 0x61, 0x70, 0x5F, 0x77, 0x72, 0x69, 0x74, 0x65, 0x72, 0x2E, 0x6C, 0x75, 0x61, 0x00],(Code::UserAppl, 15, "pcap_writer.lua")),
            (vec![0x00, 0x01, 0x00, 0x07, 0x74, 0x65, 0x73, 0x74, 0x30, 0x30, 0x32, 0x00], (Code::Comment, 7, "test002")),
        ];

        for (input, want) in tests {
            let (_, option) = option(input.leak())?;
            assert_eq!(want.0, option.code);
            assert_eq!(want.1, option.len);
            assert_eq!(
                want.2,
                String::from_utf8(option.value.split_at(option.len as usize).0.to_vec())?
            );
        }

        Ok(())
    }

    #[test]
    fn option_fails() {
        let input = vec![
            0x00, 0x42, 0x00, 0x09, 0x41, 0x70, 0x70, 0x6C, 0x65, 0x20, 0x4D, 0x42, 0x50, 0x00,
            0x00, 0x00,
        ];
        assert!(matches!(
            option(input.leak()).err(),
            Some(nom::Err::Error(Error::Option(66)))
        ));
    }
}
