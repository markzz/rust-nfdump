use crate::NfFileRecordHeader;
use byteorder::{LittleEndian, ReadBytesExt};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
#[derive(Debug, Copy, Clone)]
pub struct ExporterInfo {
    pub header: NfFileRecordHeader,
    pub version: u32,
    pub v4_addr: Option<u32>,
    pub v6_addr: Option<u128>,
    pub sa_family: u16,
    pub sysid: u16,
    pub id: u16,
}

#[derive(Debug)]
pub struct SamplerV0Record {
    pub header: NfFileRecordHeader,
    pub id: i32,
    pub interval: u32,
    pub algorithm: u16,
    pub exporter_sysid: u16,
}

#[derive(Debug)]
pub struct ExporterStatsRecord {
    pub header: NfFileRecordHeader,
    pub stat_count: u32,
    pub stat: Vec<ExporterStat>,
}

#[derive(Debug)]
pub struct ExporterStat {
    pub sysid: u32,
    pub sequence_failure: u32,
    pub packets: u64,
    pub flows: u64,
}

pub fn read_exporter_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Option<ExporterInfo> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let version = cursor.read_u32::<LittleEndian>();
    let addr_res = cursor.read_u128::<LittleEndian>();
    let sa_family = cursor.read_u16::<LittleEndian>();
    let sysid = cursor.read_u16::<LittleEndian>();
    let id = cursor.read_u16::<LittleEndian>();

    let sa = sa_family.unwrap();
    let addr = addr_res.unwrap();

    Some(ExporterInfo {
        header,
        version: version.unwrap(),
        v4_addr: {
            if sa == AF_INET6 {
                None
            } else {
                Some((addr >> 64) as u32)
            }
        },
        v6_addr: {
            if sa == AF_INET {
                None
            } else {
                Some(addr)
            }
        },
        sa_family: sa,
        sysid: sysid.unwrap(),
        id: id.unwrap(),
    })
}

pub fn read_samplerv0_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Option<SamplerV0Record> {
    let mut cursor = std::io::Cursor::new(&record_data);

    Some(SamplerV0Record {
        header,
        id: cursor.read_i32::<LittleEndian>().unwrap(),
        interval: cursor.read_u32::<LittleEndian>().unwrap(),
        algorithm: cursor.read_u16::<LittleEndian>().unwrap(),
        exporter_sysid: cursor.read_u16::<LittleEndian>().unwrap(),
    })
}

pub fn read_exporter_stats_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Option<ExporterStatsRecord> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let stat_count = cursor.read_u32::<LittleEndian>().unwrap();
    let mut stat: Vec<ExporterStat> = Vec::new();
    let mut cnt = 0;
    while cnt < stat_count {
        stat.push(ExporterStat {
            sysid: cursor.read_u32::<LittleEndian>().unwrap(),
            sequence_failure: cursor.read_u32::<LittleEndian>().unwrap(),
            packets: cursor.read_u64::<LittleEndian>().unwrap(),
            flows: cursor.read_u64::<LittleEndian>().unwrap(),
        });
        cnt += 1;
    }

    Some(ExporterStatsRecord {
        header,
        stat_count,
        stat,
    })
}
