mod block;
mod compress;
pub mod error;
mod exporter;
mod nffilev1;
mod nffilev2;
mod nfx;
pub mod record;
mod nfx_v3;

use crate::block::{DataBlock, DataBlockHeader};
use crate::compress::Decompressor;
use crate::error::NfdumpError;
use crate::error::NfdumpErrorKind::{InvalidFile, UnsupportedCompression, UnsupportedVersion, EOF};
use crate::exporter::ExporterInfo;
use crate::nffilev1::{NfFileHeaderV1, StatRecordV1};
use crate::nffilev2::{NfFileHeaderV2, StatRecordV2};
use crate::record::{RecordKind};
use byteorder::{LittleEndian, ReadBytesExt};
use std::default::Default;
use std::io::{Read, Seek, SeekFrom};

const NFFILE_V1_HEADER_SIZE: usize = 140;
const NFFILE_V2_HEADER_SIZE: usize = 40;
const NFFILE_V1_STAT_RECORD_SIZE: usize = 136;
//const NFFILE_DATA_HEADER_SIZE: usize = 12;

pub enum NfFileHeader {
    V1(NfFileHeaderV1),
    V2(NfFileHeaderV2),
}

#[derive(Debug)]
pub enum StatRecord {
    V1(StatRecordV1),
    V2(StatRecordV2),
}

pub struct NfFileReader<R> {
    reader: R,
    pub header: NfFileHeader,
    pub stat_record: StatRecord,
    data_block: Option<DataBlock>,
    remaining_blocks: u32,
    extensions: Vec<u16>,
    exporters: Vec<ExporterInfo>,
}

impl<R: Read + Seek> NfFileReader<R> {
    pub fn new(mut reader: R) -> Result<Self, NfdumpError>
    where
        R: Read + Seek,
    {
        let mut buf: Vec<u8> = vec![0; 2];
        let magic = match reader.read_exact(&mut buf) {
            Ok(_) => ((buf[1] as u16) << 8) + (buf[0]) as u16,
            Err(e) => return Err(NfdumpError::from(e)),
        };

        if magic != 0xa50c {
            return Err(NfdumpError::new(InvalidFile));
        }

        let version = match reader.read_exact(&mut buf) {
            Ok(_) => ((buf[1] as u16) << 8) + (buf[0] as u16),
            Err(e) => return Err(NfdumpError::from(e)),
        };

        let header = match version {
            0x0001 => {
                let mut hbuf = vec![0; NFFILE_V1_HEADER_SIZE - 4];
                match reader.read_exact(&mut hbuf) {
                    Ok(_) => NfFileHeader::V1(NfFileHeaderV1::from(hbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            }
            0x0002 => {
                let mut hbuf = vec![0; NFFILE_V2_HEADER_SIZE - 4];
                match reader.read_exact(&mut hbuf) {
                    Ok(_) => NfFileHeader::V2(NfFileHeaderV2::from(hbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            }
            _ => return Err(NfdumpError::new(UnsupportedVersion)),
        };

        let stat_record = match version {
            0x0001 => {
                let mut srbuf = vec![0; NFFILE_V1_STAT_RECORD_SIZE];
                match reader.read_exact(&mut srbuf) {
                    Ok(_) => StatRecord::V1(StatRecordV1::from(srbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            }
            0x0002 => {
                let x: StatRecordV2 = Default::default();
                StatRecord::V2(x)
            }
            _ => return Err(NfdumpError::new(UnsupportedVersion)),
        };

        let remaining_blocks = match &header {
            NfFileHeader::V1(h) => h.num_blocks,
            NfFileHeader::V2(h) => h.num_blocks,
        };

        let mut ret = Self {
            reader,
            header,
            stat_record,
            data_block: None,
            remaining_blocks,
            extensions: Vec::new(),
            exporters: Vec::new(),
        };

        _ = ret.read_appendix();

        Ok(ret)
    }

    pub fn get_ident(&self) -> Vec<u8> {
        match &self.header {
            NfFileHeader::V1(h) => h.ident.to_vec(),
            NfFileHeader::V2(h) => h.ident.to_vec(),
        }
    }

    fn read_appendix(&mut self) -> Result<(), NfdumpError> {
        if let NfFileHeader::V2(header) = &self.header {
            _ = self.reader.seek(SeekFrom::Start(header.off_appendix));
            for _ in 0..header.appendix_blocks {
                match self.read_data_block() {
                    Ok(_) => {
                        while let Some(r) = self.data_block.as_mut().unwrap().read_record(&self.extensions) {
                            match r {
                                RecordKind::Ident(i) => {
                                    if let NfFileHeader::V2(header) = &mut self.header {
                                        header.ident = i;
                                    }
                                }
                                RecordKind::Stat(s) => {
                                    self.stat_record = StatRecord::V2(s);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            _ = self
                .reader
                .seek(SeekFrom::Start(NFFILE_V2_HEADER_SIZE as u64));
        }

        Ok(())
    }

    fn _read_record(&mut self) -> Result<RecordKind, NfdumpError> {
        if self.data_block.is_none() && self.remaining_blocks > 0 {
            self.read_data_block()?;
        }

        match self.data_block.as_mut().unwrap().read_record(&self.extensions) {
            None => {
                self.data_block = None;
                Ok(RecordKind::None)
            }
            Some(r) => Ok(r),
        }
    }

    pub fn read_record(&mut self) -> Result<RecordKind, NfdumpError> {
        if let NfFileHeader::V2(h) = &self.header {
            if self.reader.seek(SeekFrom::Current(0)).unwrap() >= h.off_appendix {
                return Err(NfdumpError::new(EOF));
            }
        }
        loop {
            match self._read_record() {
                Ok(r) => match r {
                    RecordKind::ExtensionMap(e) => {
                        self.extensions = e.ex_id.clone();
                        continue;
                    }
                    RecordKind::ExporterInfo(e) => {
                        self.exporters.push(e.clone());
                        continue;
                    }
                    RecordKind::Record(_) => return Ok(r),
                    RecordKind::RecordV3(_) => return Ok(r),
                    RecordKind::None => {
                        return if self.remaining_blocks > 0 {
                            self.read_data_block()?;
                            self.read_record()
                        } else {
                            Err(NfdumpError::new(EOF))
                        }
                    },
                    _ => continue,
                },
                Err(e) => return Err(e),
            };
        }
    }

    fn read_data_block(&mut self) -> Result<(), NfdumpError> {
        let mut db_buf = vec![0; 12];
        self.reader.read_exact(&mut db_buf)?;

        let mut cursor = std::io::Cursor::new(db_buf);

        let num_records = cursor.read_u32::<LittleEndian>()?;
        let size = cursor.read_u32::<LittleEndian>()?;
        let id = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;

        let mut data = vec![0; size as usize];
        self.reader.read_exact(&mut data)?;

        let decompressor = NfFileReader::<R>::select_decompressor(&self.header, data)?;

        let db_header = DataBlockHeader {
            num_records,
            size,
            id,
            flags,
        };

        self.data_block = Some(DataBlock::new(db_header, decompressor));

        Ok(())
    }

    fn select_decompressor(
        header: &NfFileHeader,
        data: Vec<u8>,
    ) -> Result<Box<Decompressor>, NfdumpError> {
        match header {
            NfFileHeader::V1(h) => {
                if h.flags & 0x01 == 0x01 {
                    return Err(NfdumpError::new(UnsupportedCompression));
                }

                let decompressor: Box<Decompressor> = match h.flags & 0x18 {
                    0x08 => Box::new(Decompressor::new(2, data)?),
                    0x10 => Box::new(Decompressor::new(1, data)?),
                    _ => Box::new(Decompressor::new(3, data)?),
                };

                Ok(decompressor)
            }
            NfFileHeader::V2(h) => match h.compression {
                0 => Ok(Box::new(Decompressor::new(3, data)?)),
                1 => Err(NfdumpError::new(UnsupportedCompression)),
                2 => Ok(Box::new(Decompressor::new(2, data)?)),
                3 => Ok(Box::new(Decompressor::new(1, data)?)),
                _ => Err(NfdumpError::new(UnsupportedCompression)),
            },
        }
    }
}
