/// A [`Result`] alias where the [`Err`] case is [`openssl_rehash::Error`](crate::Error)
pub type Result<T> = std::result::Result<T, Error>;

/// The Errors that may occur when rehashing a directory
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    OpenSsl(openssl::error::ErrorStack),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Io(_) => None,
            Error::OpenSsl(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Io(ref err) => err.fmt(f),
            Error::OpenSsl(ref err) => err.fmt(f),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Error {
        Error::OpenSsl(err)
    }
}
