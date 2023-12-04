use std::io::{self, Cursor, Error, ErrorKind, Read};
use bzip2::read::BzDecoder;

const NFDUMP_COMPRESSION_TYPE_PLAIN: u8 = 3;
const NFDUMP_COMPRESSION_TYPE_LZ4: u8 = 1;
const NFDUMP_COMPRESSION_TYPE_BZ2: u8 = 2;
//const NFDUMP_COMPRESSION_TYPE_LZO: u8 = 0;

const BUFSIZE: usize = 5 * 1048576;

// Define the Decompressor enum
pub enum Decompressor {
    Lz4(Lz4Decompressor),
    Bz2(Bz2Decompressor),
    Plain(PlainDecompressor),
}

// Implement the Decompress trait for each enum variant
impl Decompressor {
    pub(crate) fn new(dtype: u8, data: Vec<u8>) -> Result<Self, Error> {
        // Match on the compression type and create the appropriate variant
        // You might need to modify this logic based on your specific requirements
        let decompressor = match dtype {
            // Example: 1 represents Lz4 compression
            NFDUMP_COMPRESSION_TYPE_LZ4 => Decompressor::Lz4(Lz4Decompressor::new(data)?),
            // Example: 2 represents Bz2 compression
            NFDUMP_COMPRESSION_TYPE_BZ2 => Decompressor::Bz2(Bz2Decompressor::new(data)?),
            // Example: 3 represents Plain compression
            NFDUMP_COMPRESSION_TYPE_PLAIN => Decompressor::Plain(PlainDecompressor::new(data)?),
            // Handle other compression types or return an error
            _ => return Err(Error::new(io::ErrorKind::InvalidData, "Unsupported compression")),
        };

        Ok(decompressor)
    }
}

// Implement the Read trait for Decompressor
impl Read for Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // Match on the enum variant and call the appropriate read method
        match self {
            Decompressor::Lz4(d) => d.read(buf),
            Decompressor::Bz2(d) => d.read(buf),
            Decompressor::Plain(d) => d.read(buf),
        }
    }
}

// Example implementations of Lz4Decompressor, Bz2Decompressor, PlainDecompressor
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

// Implement the Read trait for Lz4Decompressor
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

// use std::io::{self, Cursor, Error, Read};
// use bzip2::read::BzDecoder;
// use lz4::Decoder;
//
// pub enum Decompressor {
//     Lz4(Lz4Decompressor),
//     Bz2(Bz2Decompressor),
//     Plain(PlainDecompressor),
// }
//
// pub(crate) trait Decompressor {
//     fn new(data: Vec<u8>) -> Result<Self, io::Error>
//         where
//             Self: Sized;
// }
//
// pub struct Lz4Decompressor {
//     pub(crate) d: Decoder<Cursor<Vec<u8>>>,
// }
//
// impl Decompressor for Lz4Decompressor {
//     fn new(data: Vec<u8>) -> Result<Self, Error> {
//         let cursor = Cursor::new(data);
//         Ok(Lz4Decompressor { d: Decoder::new(cursor)? })
//     }
// }
//
//
//
// impl Decompressor for Bz2Decompressor {
//     fn new(data: Vec<u8>) -> Result<Self, Error> {
//         let cursor = Cursor::new(data);
//         Ok(Bz2Decompressor { d: BzDecoder::new(cursor) })
//     }
// }
//
// pub struct PlainDecompressor {
//     pub(crate) d: Cursor<Vec<u8>>,
// }
//
// impl Decompressor for PlainDecompressor {
//     fn new(data: Vec<u8>) -> Result<Self, Error> {
//         let cursor = Cursor::new(data);
//         Ok(PlainDecompressor { d: cursor })
//     }
// }