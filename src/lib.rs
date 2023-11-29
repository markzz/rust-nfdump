mod block;
pub mod error;
mod exporter;
mod nffilev1;
mod nffilev2;
mod nfx;
pub mod record;

use crate::block::DataBlockHeader;
use crate::error::NfdumpError;
use crate::error::NfdumpErrorKind::{UnsupportedVersion, EOF, InvalidFile};
use crate::exporter::{
    read_exporter_record, read_exporter_stats_record, read_samplerv0_record, ExporterInfo,
};
use crate::nffilev1::{NfFileHeaderV1, StatRecordV1};
use crate::nffilev2::{NfFileHeaderV2, StatRecordV2};
use crate::nfx::read_extension_map;
use crate::record::{new_record, Record};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

const NFFILE_V1_HEADER_SIZE: usize = 140;
const NFFILE_V2_HEADER_SIZE: usize = 40;
const NFFILE_V1_STAT_RECORD_SIZE: usize = 136;
const NFFILE_V2_STAT_RECORD_SIZE: usize = 144;
const NFFILE_DATA_HEADER_SIZE: usize = 12;

pub enum NfFileHeader {
    V1(NfFileHeaderV1),
    V2(NfFileHeaderV2),
}

pub enum StatRecord {
    V1(StatRecordV1),
    V2(StatRecordV2),
}

#[derive(Debug, Copy, Clone)]
pub struct NfFileRecordHeader {
    pub rtype: u16,
    pub size: u16,
}

pub struct NfFileReader<R> {
    reader: R,
    pub header: NfFileHeader,
    pub stat_record: StatRecord,
    data_block: DataBlockHeader,
    extensions: Vec<u16>,
    exporters: Vec<ExporterInfo>,
}

impl<R: Read> NfFileReader<R> {
    pub fn new(mut reader: R) -> Result<NfFileReader<R>, NfdumpError> {
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
            },
            0x0002 => {
                let mut hbuf = vec![0; NFFILE_V2_HEADER_SIZE - 4];
                match reader.read_exact(&mut hbuf) {
                    Ok(_) => NfFileHeader::V2(NfFileHeaderV2::from(hbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            },
            _ => return Err(NfdumpError::new(UnsupportedVersion)),
        };

        let stat_record = match version {
            0x0001 => {
                let mut srbuf = vec![0; NFFILE_V1_STAT_RECORD_SIZE];
                match reader.read_exact(&mut srbuf) {
                    Ok(_) => StatRecord::V1(StatRecordV1::from(srbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            },
            0x0002 => {
                let mut srbuf = vec![0; NFFILE_V2_STAT_RECORD_SIZE];
                match reader.read_exact(&mut srbuf) {
                    Ok(_) => StatRecord::V2(StatRecordV2::from(srbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            },
            _ => return Err(NfdumpError::new(UnsupportedVersion)),
        };

        let data_block = DataBlockHeader {
            num_records: 0,
            size: 0,
            id: 0,
            flags: 0,
            record_num: 0,
            block_num: 0,
        };

        Ok(NfFileReader {
            reader,
            header,
            stat_record,
            data_block,
            extensions: Vec::new(),
            exporters: Vec::new(),
        })
    }

    pub fn read_record(&mut self) -> Result<Record, NfdumpError> {
        if self.data_block.record_num == 0
            || self.data_block.record_num == self.data_block.num_records
        {
            self.data_block = match self.read_data_block_header() {
                Ok(db) => db,
                Err(e) => return Err(e),
            };
        }

        self.data_block.record_num += 1;

        let mut record_header_data = [0; 4];
        let result = self.reader.read_exact(&mut record_header_data);

        let record_header = match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&record_header_data);

                Ok(NfFileRecordHeader {
                    rtype: cursor.read_u16::<LittleEndian>()?,
                    size: cursor.read_u16::<LittleEndian>()?,
                })
            }
            Err(e) => Err(e),
        };

        let header = record_header.unwrap();
        let mut record_data = vec![0; header.size as usize - 4];
        match self.reader.read_exact(&mut record_data) {
            Ok(()) => {
                if header.rtype == 9 {
                    // TODO: The result of this function is 100% ignored
                    read_samplerv0_record(header, record_data)?;
                } else if header.rtype == 7 {
                    let exporter = read_exporter_record(header, record_data)?;
                    self.exporters.push(exporter.clone());
                } else if header.rtype == 2 {
                    // TODO: This assumes there will only ever be one extension map per file.
                    let extension_map = read_extension_map(header, record_data)?;
                    self.extensions = extension_map.ex_id.clone();
                } else if header.rtype == 8 {
                    // TODO: The result of this function is 100% ignored
                    read_exporter_stats_record(header, record_data)?;
                } else {
                    return new_record(header, record_data, &(self.extensions));
                }
                self.read_record()
            }
            Err(e) => Err(NfdumpError::from(e)),
        }
    }

    fn read_data_block_header(&mut self) -> Result<DataBlockHeader, NfdumpError> {
        let mut block_data = [0; NFFILE_DATA_HEADER_SIZE];
        let result = self.reader.read_exact(&mut block_data);

        let num_blocks = match &self.header {
            NfFileHeader::V1(h) => h.num_blocks,
            NfFileHeader::V2(h) => h.num_blocks,
        };

        if self.data_block.block_num == num_blocks {
            return Err(NfdumpError::new(EOF));
        }

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&block_data);

                Ok(DataBlockHeader {
                    num_records: cursor.read_u32::<LittleEndian>()?,
                    size: cursor.read_u32::<LittleEndian>()?,
                    id: cursor.read_u16::<LittleEndian>()?,
                    flags: cursor.read_u16::<LittleEndian>()?,
                    record_num: 0,
                    block_num: self.data_block.block_num + 1,
                })
            }
            Err(e) => Err(NfdumpError::from(e)),
        }
    }
}
