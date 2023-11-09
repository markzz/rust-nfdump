mod exporter;
mod record_types;
mod nfx;

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Error, Read, Seek};
use crate::exporter::{ExporterInfoRecordV1, ExporterStatsRecord, read_exporter_record, read_exporter_stats_record, read_samplerv0_record, SamplerV0Record};
use crate::nfx::{ExtensionMap, read_extension_map};

const NFFILE_V1_HEADER_SIZE: usize = 140;
const NFFILE_V1_STAT_RECORD_SIZE: usize = 136;
const NFFILE_V1_DATA_HEADER_SIZE: usize = 12;

pub struct NfFileHeaderV1 {
    pub magic: u16,
    pub version: u16,
    pub flags: u32,
    pub num_blocks: u32,
    pub ident: [u8; 128]
}

pub struct StatRecordV1 {
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

struct DataBlockHeaderV1 {
    num_records: u32,
    size: u32,
    id: u16,
    flags: u16,
    record_num: u32,
}

#[derive(Debug, Copy, Clone)]
pub struct NfFileRecordHeaderV1 {
    pub rtype: u16,
    pub size: u16,
}

pub enum NfFileRecord {
    NfFileRecordV1(NfFileRecordV1),
    ExporterInfoRecordV1(ExporterInfoRecordV1),
    ExtensionMap(ExtensionMap),
    SamplerV0Record(SamplerV0Record),
    ExporterStatsRecord(ExporterStatsRecord),
}

#[derive(Debug)]
pub struct NfFileRecordV1 {
    pub head: NfFileRecordHeaderV1,
    pub flags: u16,
    pub ext_map: u16,
    pub msec_first: u16,
    pub msec_last: u16,
    pub first: u32,
    pub last: u32,
    pub fwd_status: u8,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub exporter_sysid: u16,
    pub bi_flow_dir: u8,
    pub flow_end_reason: u8,
    pub ip4_addr: Option<IPv4Addrs>,
    pub ip6_addr: Option<IPv6Addrs>,
    pub packets: u64,
    pub bytes: u64,
    pub input: u32,
    pub output: u32,
    pub src_as: u32,
    pub dst_as: u32,
}

#[derive(Debug)]
pub struct IPv4Addrs {
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[derive(Debug)]
pub struct IPv6Addrs {
    pub src_addr: u128,
    pub dst_addr: u128,
}
pub struct NfFileReaderV1<R> {
    reader: R,
    pub header: NfFileHeaderV1,
    pub stat_record: StatRecordV1,
    data_block: DataBlockHeaderV1,
    extensions: Vec<u16>,
    exporters: Vec<ExporterInfoRecordV1>,
}

impl<R: Read> NfFileReaderV1<R> {
    pub fn new(mut reader: R) -> NfFileReaderV1<R> {
        let header = NfFileReaderV1::read_header(&mut reader).unwrap().unwrap();
        let stat_record = NfFileReaderV1::read_stat_record(&mut reader).unwrap().unwrap();
        let data_block = DataBlockHeaderV1 {
            num_records: 0,
            size: 0,
            id: 0,
            flags: 0,
            record_num: 0,
        };

        NfFileReaderV1 {
            reader,
            header,
            stat_record,
            data_block,
            extensions: Vec::new(),
            exporters: Vec::new()
        }
    }

    pub fn read_record(&mut self) -> Result<Option<NfFileRecord>, Error> {
        if self.data_block.record_num == 0 || self.data_block.record_num == self.data_block.num_records {
            let db = self.read_data_block_header().unwrap();
            match db {
                None => return Ok(None),
                _ => self.data_block = db.unwrap(),
            };
        }

        self.data_block.record_num += 1;

        let mut record_header_data = [0; 4];
        let result = self.reader.read_exact(&mut record_header_data);

        let record_header = match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&record_header_data);

                Ok(Some(NfFileRecordHeaderV1 {
                    rtype: cursor.read_u16::<LittleEndian>()?,
                    size: cursor.read_u16::<LittleEndian>()?,
                }))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        };

        let header = record_header.unwrap().unwrap();
        let mut record_data = vec![0; header.size as usize - 4];
        let result = self.reader.read_exact(&mut record_data);

        match result {
            Ok(_) => {
                if header.rtype == 9 {
                    Ok(read_samplerv0_record(header, record_data))
                } else if header.rtype == 7 {
                    // See block below for similar sentiment.
                    let exporter = read_exporter_record(header, record_data).unwrap();
                    match &exporter {
                        NfFileRecord::ExporterInfoRecordV1(ex) => {
                            self.exporters.push(ex.clone());
                        }
                        _ => {}
                    }
                    Ok(Option::from(exporter))
                } else if header.rtype == 2 {
                    // This does not "look right" to me. If someone who sees this knows the idiomatic
                    // way to handle what this is doing, I'd love to see it. For now, it works and
                    // it'll continue to exist here.
                    // TODO: This assumes there will only ever be one extension map per file.
                    let extension_map = read_extension_map(header, record_data).unwrap();
                    match &extension_map {
                        NfFileRecord::ExtensionMap(em) => {
                            self.extensions = em.ex_id.clone();
                        }
                        _ => {}
                    }
                    Ok(Option::from(extension_map))
                } else if header.rtype == 8 {
                    Ok(read_exporter_stats_record(header, record_data))
                } else {
                    let mut cursor = std::io::Cursor::new(&record_data);
                    let flags = cursor.read_u16::<LittleEndian>()?;

                    Ok(Some(NfFileRecord::NfFileRecordV1( NfFileRecordV1 {
                        head: header,
                        flags,
                        ext_map: cursor.read_u16::<LittleEndian>()?,
                        msec_first: cursor.read_u16::<LittleEndian>()?,
                        msec_last: cursor.read_u16::<LittleEndian>()?,
                        first: cursor.read_u32::<LittleEndian>()?,
                        last: cursor.read_u32::<LittleEndian>()?,
                        fwd_status: cursor.read_u8()?,
                        tcp_flags: cursor.read_u8()?,
                        prot: cursor.read_u8()?,
                        tos: cursor.read_u8()?,
                        src_port: cursor.read_u16::<LittleEndian>()?,
                        dst_port: cursor.read_u16::<LittleEndian>()?,
                        exporter_sysid: cursor.read_u16::<LittleEndian>()?,
                        bi_flow_dir: cursor.read_u8()?,
                        flow_end_reason: cursor.read_u8()?,
                        ip4_addr: {
                            if flags & 0x01 != 0 {
                                None
                            } else {
                                Some(IPv4Addrs {
                                    src_addr: cursor.read_u32::<LittleEndian>()?,
                                    dst_addr: cursor.read_u32::<LittleEndian>()?,
                                })
                            }
                        },
                        ip6_addr: {
                            if flags & 0x01 == 0 {
                                None
                            } else {
                                Some(IPv6Addrs {
                                    src_addr: cursor.read_u128::<LittleEndian>()?,
                                    dst_addr: cursor.read_u128::<LittleEndian>()?,
                                })
                            }
                        },
                        packets: {
                            if flags & 0x02 == 0 {
                                cursor.read_u32::<LittleEndian>()? as u64
                            } else {
                                cursor.read_u64::<LittleEndian>()?
                            }
                        },
                        bytes: {
                            if flags & 0x04 == 0 {
                                cursor.read_u32::<LittleEndian>()? as u64
                            } else {
                                cursor.read_u64::<LittleEndian>()?
                            }
                        },
                        input: {
                            if self.extensions.contains(&4u16) {
                                cursor.read_u16::<LittleEndian>()? as u32
                            } else if self.extensions.contains(&5u16) {
                                cursor.read_u32::<LittleEndian>()?
                            } else {
                                0u32
                            }
                        },
                        output: {
                            if self.extensions.contains(&4u16) {
                                cursor.read_u16::<LittleEndian>()? as u32
                            } else if self.extensions.contains(&5u16) {
                                cursor.read_u32::<LittleEndian>()?
                            } else {
                                0u32
                            }
                        },
                        src_as: {
                            if self.extensions.contains(&6u16) {
                                cursor.read_u16::<LittleEndian>()? as u32
                            } else if self.extensions.contains(&7u16) {
                                cursor.read_u32::<LittleEndian>()?
                            } else {
                                0u32
                            }
                        },
                        dst_as: {
                            if self.extensions.contains(&6u16) {
                                cursor.read_u16::<LittleEndian>()? as u32
                            } else if self.extensions.contains(&7u16) {
                                cursor.read_u32::<LittleEndian>()?
                            } else {
                                0u32
                            }
                        },
                        // TODO: Implement extensions
                    })))
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn read_data_block_header(&mut self) -> Result<Option<DataBlockHeaderV1>, Error> {
        let mut block_data = [0; NFFILE_V1_DATA_HEADER_SIZE];
        let result = self.reader.read_exact(&mut block_data);

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&block_data);

                Ok(Some(DataBlockHeaderV1 {
                    num_records: cursor.read_u32::<LittleEndian>()?,
                    size: cursor.read_u32::<LittleEndian>()?,
                    id: cursor.read_u16::<LittleEndian>()?,
                    flags: cursor.read_u16::<LittleEndian>()?,
                    record_num: 0,
                }))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn read_header(mut reader: R) -> Result<Option<NfFileHeaderV1>, Error> {
        let mut header_data = [0; NFFILE_V1_HEADER_SIZE];
        let result = reader.read_exact(&mut header_data);

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&header_data);

                Ok(Some(NfFileHeaderV1 {
                    magic: cursor.read_u16::<LittleEndian>()?,
                    version: cursor.read_u16::<LittleEndian>()?,
                    flags: cursor.read_u32::<LittleEndian>()?,
                    num_blocks: cursor.read_u32::<LittleEndian>()?,
                    ident: {
                        let mut arr: [u8; 128] = [0; 128];
                        _ = cursor.read_exact(&mut arr);
                        arr
                    },
                }))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn read_stat_record(mut reader: R) -> Result<Option<StatRecordV1>, Error> {
        let mut stat_record_data = [0; NFFILE_V1_STAT_RECORD_SIZE];
        let result = reader.read_exact(&mut stat_record_data);

        match result {
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(&stat_record_data);

                Ok(Some(StatRecordV1 {
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
                }))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
