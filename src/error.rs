use crate::error::NfdumpErrorKind::IoError;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub struct NfdumpError {
    pub(crate) kind: NfdumpErrorKind,
    pub(crate) io_error: Option<std::io::Error>,
}

#[derive(Debug)]
pub enum NfdumpErrorKind {
    EOF,
    IoError,
    InvalidFile,
    UnexpectedSAInExporter,
    ParseError,
}

impl Display for NfdumpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            NfdumpErrorKind::EOF => {
                write!(f, "{}", "no more records to read (end of file)")
            }
            NfdumpErrorKind::UnexpectedSAInExporter => {
                write!(f, "{}", "unexpected sa value in exporter record")
            }
            NfdumpErrorKind::ParseError => {
                write!(f, "{}", "parser error")
            }
            IoError => match self.io_error {
                Some(ref e) => write!(f, "{}", e),
                _ => Ok(()),
            },
            NfdumpErrorKind::InvalidFile => {
                write!(f, "{}", "")
            }
        }
    }
}

impl std::error::Error for NfdumpError {}

impl From<std::io::Error> for NfdumpError {
    fn from(value: std::io::Error) -> Self {
        let io_error = Option::from(value);
        let kind = IoError;

        NfdumpError { kind, io_error }
    }
}

impl NfdumpError {
    pub(crate) fn new(kind: NfdumpErrorKind) -> Self {
        NfdumpError {
            kind,
            io_error: None,
        }
    }
}
