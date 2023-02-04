pub type Result<T, I> = std::result::Result<T, Error<I>>;

#[derive(Debug, thiserror::Error)]
pub enum Error<I>
where
    I: Sized,
{
    /// Invalid block type
    #[error("Invalid block type {0:?}")]
    Type(u32),

    /// Input parse error
    #[error("Input parse error {0:?}")]
    Parse(#[from] nom::error::VerboseError<I>),

    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
