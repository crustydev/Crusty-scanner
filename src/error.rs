use thiserror::Error;



/// Struct for error reporting.
/// 
#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}, File Open Error")]
    FileOpenError(String),
    #[error("{0}, Invalid HTTP response")]
    InvalidHttpResponse(String),
    #[error("{0}, Reqwest Error")]
    ReqwestError(String),
    #[error("{0}, Tokio Error")]
    TokioJoinError(String),
}

/// Converts tokioJoinError to custom enum Error for uniform reporting
/// 
impl std::convert::From<tokio::task::JoinError> for Error {
    fn from(error_message: tokio::task::JoinError) -> Self {
        return Error::TokioJoinError(error_message.to_string());
    }
}

/// Converts reqwestError to custom enum Error for uniform reporting
impl std::convert::From<reqwest::Error> for Error {
    fn from(error_message: reqwest::Error) -> Self {
        return Error::ReqwestError(error_message.to_string());
    }
}


/// Converts std::io::error to custom enum Error for uniform reporting
/// 
impl std::convert::From<std::io::Error> for Error {
    fn from(error_message: std::io::Error) -> Self {
        return Error::FileOpenError(error_message.to_string());
    }
}