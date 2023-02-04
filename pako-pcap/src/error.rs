pub type Result<'a, T, I = &'a[u8]> = std::result::Result<T, Error<I>>;

#[derive(Debug, thiserror::Error)]
pub enum Error<I>
where
    I: Sized,
{
    /// Input parse error
    #[error("Input parse error {0:?}")]
    Parse(#[from] nom::error::VerboseError<I>),

    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
