pub mod error;
mod exporter;
mod nfx;
pub mod record;

use crate::error::NfdumpError;
use crate::exporter::{
    read_exporter_record, read_exporter_stats_record, read_samplerv0_record, ExporterInfo,
};
use crate::nfx::read_extension_map;
use crate::record::{new_record, Record};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;
use crate::error::NfdumpErrorKind::EOF;

const NFFILE_HEADER_SIZE: usize = 140;
const NFFILE_STAT_RECORD_SIZE: usize = 136;
const NFFILE_DATA_HEADER_SIZE: usize = 12;

pub struct NfFileHeader {
    pub magic: u16,
    pub version: u16,
    pub flags: u32,
    pub num_blocks: u32,
    pub ident: [u8; 128],
}

pub struct StatRecord {
    pub flows: u64,
    pub bytes: u64,
    pub packets: u64,

    pub flows_tcp: u64,
    pub flows_udp: u64,
    pub flows_icmp: u64,
    pub flows_other: u64,

    pub bytes_tcp: u64,
    pub bytes_udp: u64,
    pub bytes_icmp: u64,
    pub bytes_other: u64,

    pub packets_tcp: u64,
    pub packets_udp: u64,
    pub packets_icmp: u64,
    pub packets_other: u64,

    pub first_seen: u32,
    pub last_seen: u32,
    pub msec_first: u16,
    pub msec_last: u16,

    pub sequence_failure: u32,
}

struct DataBlockHeader {
    num_records: u32,
    size: u32,
    id: u16,
    flags: u16,
    record_num: u32,
    block_num: u32,
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
    pub fn new(mut reader: R) -> NfFileReader<R> {
        let header = NfFileReader::read_header(&mut reader).unwrap();
        let stat_record = NfFileReader::read_stat_record(&mut reader)
            .unwrap();
        let data_block = DataBlockHeader {
            num_records: 0,
            size: 0,
            id: 0,
            flags: 0,
            record_num: 0,
            block_num: 0,
        };

        NfFileReader {
            reader,
            header,
            stat_record,
            data_block,
            extensions: Vec::new(),
            exporters: Vec::new(),
        }
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
                    read_samplerv0_record(header, record_data);
                } else if header.rtype == 7 {
                    let exporter = read_exporter_record(header, record_data).unwrap();
                    self.exporters.push(exporter.clone());
                } else if header.rtype == 2 {
                    // TODO: This assumes there will only ever be one extension map per file.
                    let extension_map = read_extension_map(header, record_data).unwrap();
                    self.extensions = extension_map.ex_id.clone();
                } else if header.rtype == 8 {
                    // TODO: The result of this function is 100% ignored
                    read_exporter_stats_record(header, record_data);
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

        if self.data_block.block_num == self.header.num_blocks {
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
            },
            Err(e) => Err(NfdumpError::from(e)),
        }
    }

    fn read_header(mut reader: R) -> Result<NfFileHeader, NfdumpError> {
        let mut header_data = [0; NFFILE_HEADER_SIZE];
        let result = reader.read_exact(&mut header_data);

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&header_data);

                Ok(NfFileHeader {
                    magic: cursor.read_u16::<LittleEndian>()?,
                    version: cursor.read_u16::<LittleEndian>()?,
                    flags: cursor.read_u32::<LittleEndian>()?,
                    num_blocks: cursor.read_u32::<LittleEndian>()?,
                    ident: {
                        let mut arr: [u8; 128] = [0; 128];
                        _ = cursor.read_exact(&mut arr);
                        arr
                    },
                })
            },
            Err(e) => Err(NfdumpError::from(e)),
        }
    }

    fn read_stat_record(mut reader: R) -> Result<StatRecord, NfdumpError> {
        let mut stat_record_data = [0; NFFILE_STAT_RECORD_SIZE];
        let result = reader.read_exact(&mut stat_record_data);

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&stat_record_data);

                Ok(StatRecord {
                    flows: cursor.read_u64::<LittleEndian>()?,
                    bytes: cursor.read_u64::<LittleEndian>()?,
                    packets: cursor.read_u64::<LittleEndian>()?,
                    flows_tcp: cursor.read_u64::<LittleEndian>()?,
                    flows_udp: cursor.read_u64::<LittleEndian>()?,
                    flows_icmp: cursor.read_u64::<LittleEndian>()?,
                    flows_other: cursor.read_u64::<LittleEndian>()?,
                    bytes_tcp: cursor.read_u64::<LittleEndian>()?,
                    bytes_udp: cursor.read_u64::<LittleEndian>()?,
                    bytes_icmp: cursor.read_u64::<LittleEndian>()?,
                    bytes_other: cursor.read_u64::<LittleEndian>()?,
                    packets_tcp: cursor.read_u64::<LittleEndian>()?,
                    packets_udp: cursor.read_u64::<LittleEndian>()?,
                    packets_icmp: cursor.read_u64::<LittleEndian>()?,
                    packets_other: cursor.read_u64::<LittleEndian>()?,
                    first_seen: cursor.read_u32::<LittleEndian>()?,
                    last_seen: cursor.read_u32::<LittleEndian>()?,
                    msec_first: cursor.read_u16::<LittleEndian>()?,
                    msec_last: cursor.read_u16::<LittleEndian>()?,
                    sequence_failure: cursor.read_u32::<LittleEndian>()?,
                })
            }
            Err(e) => Err(NfdumpError::from(e)),
        }
    }
}
