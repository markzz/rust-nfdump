use std::io::{self, Cursor, Error, ErrorKind, Read};
use bzip2::read::BzDecoder;

pub(crate) const NFDUMP_COMPRESSION_TYPE_PLAIN: u8 = 0;
pub(crate) const NFDUMP_COMPRESSION_TYPE_LZO: u8 = 1;
pub(crate) const NFDUMP_COMPRESSION_TYPE_BZ2: u8 = 2;
pub(crate) const NFDUMP_COMPRESSION_TYPE_LZ4: u8 = 3;

const BUFSIZE: usize = 5 * 1048576;

pub enum Decompressor {
    Lzo(LzoDecompressor),
    Lz4(Lz4Decompressor),
    Bz2(Bz2Decompressor),
    Plain(PlainDecompressor),
}

impl Decompressor {
    pub(crate) fn new(dtype: u8, data: Vec<u8>) -> Result<Self, Error> {
        let decompressor = match dtype {
            NFDUMP_COMPRESSION_TYPE_LZO => Decompressor::Lzo(LzoDecompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_LZ4 => Decompressor::Lz4(Lz4Decompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_BZ2 => Decompressor::Bz2(Bz2Decompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_PLAIN => Decompressor::Plain(PlainDecompressor::new(data)?),
            _ => return Err(Error::new(io::ErrorKind::InvalidData, "Unsupported compression")),
        };

        Ok(decompressor)
    }
}

impl Read for Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Decompressor::Lz4(d) => d.read(buf),
            Decompressor::Bz2(d) => d.read(buf),
            Decompressor::Plain(d) => d.read(buf),
            Decompressor::Lzo(d) => d.read(buf),
        }
    }
}

pub struct LzoDecompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl LzoDecompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let decompressed = minilzo::decompress(data.as_slice(), BUFSIZE).unwrap();
        let d = Cursor::new(decompressed);
        Ok(LzoDecompressor { d })
    }
}

impl Read for LzoDecompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.d.read(buf)
    }
}

pub struct Lz4Decompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl Lz4Decompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let mut out: [u8; BUFSIZE] = [0; BUFSIZE];
        let size = match lz4_flex::block::decompress_into(&data, &mut out) {
            Ok(s) => s,
            Err(_) => 0,
        };

        match size {
            1.. => {
                let trimmed_vec = out[..size].to_vec();
                let d = Cursor::new(trimmed_vec);
                Ok(Lz4Decompressor { d })
            },
            _ => {
                Err(Error::new(ErrorKind::InvalidData, "Lz4 decompression failed"))
            },
        }
    }
}

impl Read for Lz4Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.d.read(buf)
    }
}

pub struct Bz2Decompressor {
    pub(crate) d: BzDecoder<Cursor<Vec<u8>>>,
}

impl Bz2Decompressor {
    pub(crate) fn new(data: Vec<u8>) -> Result<Self, Error> {
        let cursor = Cursor::new(data);
        Ok(Bz2Decompressor { d: BzDecoder::new(cursor) })
    }
}

impl Read for Bz2Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.d.read(buf)
    }
}

pub struct PlainDecompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl PlainDecompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let cursor = Cursor::new(data);
        Ok(PlainDecompressor { d: cursor })
    }
}
impl Read for PlainDecompressor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.d.read(buf)
    }
}