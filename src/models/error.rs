use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("API Response Error: {0}")]
    ApiResponseReqwestError(#[from] reqwest::Error),

    #[error("API Response Parse Error: {0}")]
    ApiResponseParseError(String),

    #[error("API Response Unknown Error: {0}")]
    ApiResponseUnknownError(String),

    #[error("Unauthorized Error")]
    UnauthorizedError,

    #[error("Unknown CLI Error")]
    UnknownError,

    #[error("Http Error: {0}")]
    HttpError(String),
}
