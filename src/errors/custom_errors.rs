use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Unknown error occurred")]
    Unknown,
}
