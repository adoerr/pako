use nom::error::{ErrorKind, ParseError};

pub type Result<T, I> = std::result::Result<T, Error<I>>;

#[derive(Debug, thiserror::Error)]
pub enum Error<I>
where
    I: Sized,
{
    /// Invalid block type
    #[error("Invalid block type {0:?}")]
    Type(u32),

    /// Invalid option type
    #[error("Invalid option type {0:?}")]
    Option(u16),

    /// Nom parser error
    #[error("Nom parser error {0:?}")]
    Nom(I, ErrorKind),

    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl<I> ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Error::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

#[cfg(test)]
mod tests {
    use nom::{Err::Error as NomError, IResult};

    use crate::Error;

    fn test_parse(_input: &str) -> IResult<&str, &str, Error<&str>> {
        Err(NomError(Error::Option(42)))
    }

    #[test]
    fn error_works() {
        match test_parse("").unwrap_err() {
            NomError(e) => assert!(matches!(e, Error::Option(42))),
            _ => panic!("invalid error"),
        }
    }
}
