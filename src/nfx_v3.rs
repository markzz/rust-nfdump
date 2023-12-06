// dead code is allowed in this file as it is verified to not have anything dead
// except some of the extensions which are not implemented yet
#![allow(dead_code)]

use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{LittleEndian, ReadBytesExt};
use crate::error::NfdumpError;
use crate::record::NfFileRecordHeader;

const EXT_NULL: u16 = 0x0;
const EXT_GENERIC_FLOW: u16 = 0x1;
const EXT_IPV4_FLOW: u16 = 0x2;
const EXT_IPV6_FLOW: u16 = 0x3;
const EXT_FLOW_MISC: u16 = 0x4;
const EXT_CNT_FLOW: u16 = 0x5;
const EXT_VLAN_FLOW: u16 = 0x6;
const EXT_AS_ROUTING: u16 = 0x7;
const EXT_BGP_NEXT_HOP_V4: u16 = 0x8;
const EXT_BGP_NEXT_HOP_V6: u16 = 0x9;
const EXT_IP_NEXT_HOP_V4: u16 = 0xa;
const EXT_IP_NEXT_HOP_V6: u16 = 0xb;
const EXT_IP_RECEIVED_V4: u16 = 0xc;
const EXT_IP_RECEIVED_V6: u16 = 0xd;
const EXT_SAMPLER_INFO: u16 = 0x12;
const EXT_IN_PAYLOAD: u16 = 0x1d;
const EXT_NSEL_X_LATE_IPV4: u16 = 0x14;
const EXT_NSEL_X_LATE_IPV6: u16 = 0x15;
const EXT_NSEL_X_LATE_PORT: u16 = 0x16;

#[derive(Debug)]
pub struct RecordHeaderV3 {
    pub header: NfFileRecordHeader,
    pub num_elements: u16,
    pub engine_type: u8,
    pub engine_id: u8,
    pub exporter_id: u16,
    pub flags: u8,
    pub nf_version: u8,
}

#[derive(Debug)]
pub struct ExGenericFlow {
    pub msec_first: u64,
    pub msec_last: u64,
    pub msec_received: u64,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub tcp_flags: u8,
    pub fwd_status: u8,
    pub src_tos: u8,
}

#[derive(Debug)]
pub struct ExIpv4Flow {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct ExIpv6Flow {
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

#[derive(Debug)]
pub struct ExFlowMisc {
    pub input: u32,
    pub output: u32,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub dir: u8,
    pub dst_tos: u8,
    pub bi_flow_dir: u8,
    pub flow_end_reason: u8,
    pub rev_tcp_flags: u8,
    pub fill: u8,
}

#[derive(Debug)]
pub struct ExCntFlow {
    pub flows: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

#[derive(Debug)]
pub struct ExVlan {
    pub src_vlan: u32,
    pub dst_vlan: u32,
}

#[derive(Debug)]
pub struct ExAsRouting {
    pub src_as: u32,
    pub dst_as: u32,
}

#[derive(Debug)]
pub struct ExSamplerInfo {
    pub selector_id: u64,
    pub sysid: u16,
    pub align: u16,
}

#[derive(Debug)]
pub struct ExNselXLatePort {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug)]
pub struct ExBgpNextHop {
    pub ip: IpAddr,
}

#[derive(Debug)]
pub struct ExIpNextHop {
    pub ip: IpAddr,
}

#[derive(Debug)]
pub struct ExIpReceived {
    pub ip: IpAddr,
}

pub type ExInPayload = Vec<u8>;

pub type ExNselXLateIpv4 = [u32; 10];

pub type ExNselXLateIpv6 = [u128; 10];

/// `Record` represents a flow record.
#[derive(Debug)]
pub struct RecordV3 {
    pub head: RecordHeaderV3,
    pub generic_flow: Option<ExGenericFlow>,
    pub ipv4_flow: Option<ExIpv4Flow>,
    pub ipv6_flow: Option<ExIpv6Flow>,
    pub flow_misc: Option<ExFlowMisc>,
    pub cnt_flow: Option<ExCntFlow>,
    pub vlan: Option<ExVlan>,
    pub as_routing: Option<ExAsRouting>,
    pub sampler_info: Option<ExSamplerInfo>,
    pub nsel_xlate_port: Option<ExNselXLatePort>,
    pub bgp_next_hop: Option<ExBgpNextHop>,
    pub ip_next_hop: Option<ExIpNextHop>,
    pub ip_received: Option<ExIpReceived>,
    pub in_payload: Option<ExInPayload>,
}

impl RecordV3 {
    pub fn new(header: NfFileRecordHeader, data: Vec<u8>) -> Result<RecordV3, NfdumpError> {
        let mut cursor = Cursor::new(&data);

        let v3_header = RecordHeaderV3 {
            header,
            num_elements: cursor.read_u16::<LittleEndian>()?,
            engine_type: cursor.read_u8()?,
            engine_id: cursor.read_u8()?,
            exporter_id: cursor.read_u16::<LittleEndian>()?,
            flags: cursor.read_u8()?,
            nf_version: cursor.read_u8()?,
        };

        let mut record = RecordV3 {
            head: v3_header,
            generic_flow: None,
            ipv4_flow: None,
            ipv6_flow: None,
            flow_misc: None,
            cnt_flow: None,
            vlan: None,
            as_routing: None,
            sampler_info: None,
            nsel_xlate_port: None,
            bgp_next_hop: None,
            ip_next_hop: None,
            ip_received: None,
            in_payload: None,
        };

        let mut cnt = 0;
        while cnt < record.head.num_elements {
            cnt += 1;
            let ext = cursor.read_u16::<LittleEndian>()?;

            // Skip record size, it's rather redundant
            let size = cursor.read_u16::<LittleEndian>()?;

            match ext {
                EXT_GENERIC_FLOW => {
                    record.generic_flow = Some(ExGenericFlow {
                        msec_first: cursor.read_u64::<LittleEndian>()?,
                        msec_last: cursor.read_u64::<LittleEndian>()?,
                        msec_received: cursor.read_u64::<LittleEndian>()?,
                        in_packets: cursor.read_u64::<LittleEndian>()?,
                        in_bytes: cursor.read_u64::<LittleEndian>()?,
                        src_port: cursor.read_u16::<LittleEndian>()?,
                        dst_port: cursor.read_u16::<LittleEndian>()?,
                        proto: cursor.read_u8()?,
                        tcp_flags: cursor.read_u8()?,
                        fwd_status: cursor.read_u8()?,
                        src_tos: cursor.read_u8()?,
                    });
                }
                EXT_IPV4_FLOW => {
                    record.ipv4_flow = Some(ExIpv4Flow {
                        src_addr: Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?),
                        dst_addr: Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?),
                    });
                }
                EXT_IPV6_FLOW => {
                    record.ipv6_flow = Some(ExIpv6Flow {
                        src_addr: Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?),
                        dst_addr: Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?),
                    });
                }
                EXT_FLOW_MISC => {
                    record.flow_misc = Some(ExFlowMisc {
                        input: cursor.read_u32::<LittleEndian>()?,
                        output: cursor.read_u32::<LittleEndian>()?,
                        src_mask: cursor.read_u8()?,
                        dst_mask: cursor.read_u8()?,
                        dir: cursor.read_u8()?,
                        dst_tos: cursor.read_u8()?,
                        bi_flow_dir: cursor.read_u8()?,
                        flow_end_reason: cursor.read_u8()?,
                        rev_tcp_flags: cursor.read_u8()?,
                        fill: cursor.read_u8()?,
                    });
                }
                EXT_CNT_FLOW => {
                    record.cnt_flow = Some(ExCntFlow {
                        flows: cursor.read_u64::<LittleEndian>()?,
                        out_packets: cursor.read_u64::<LittleEndian>()?,
                        out_bytes: cursor.read_u64::<LittleEndian>()?,
                    });
                }
                EXT_VLAN_FLOW => {
                    record.vlan = Some(ExVlan {
                        src_vlan: cursor.read_u32::<LittleEndian>()?,
                        dst_vlan: cursor.read_u32::<LittleEndian>()?,
                    });
                }
                EXT_AS_ROUTING => {
                    record.as_routing = Some(ExAsRouting {
                        src_as: cursor.read_u32::<LittleEndian>()?,
                        dst_as: cursor.read_u32::<LittleEndian>()?,
                    });
                }
                EXT_SAMPLER_INFO => {
                    record.sampler_info = Some(ExSamplerInfo {
                        selector_id: cursor.read_u64::<LittleEndian>()?,
                        sysid: cursor.read_u16::<LittleEndian>()?,
                        align: cursor.read_u16::<LittleEndian>()?,
                    });
                }
                EXT_NSEL_X_LATE_PORT => {
                    record.nsel_xlate_port = Some(ExNselXLatePort {
                        src_port: cursor.read_u16::<LittleEndian>()?,
                        dst_port: cursor.read_u16::<LittleEndian>()?,
                    });
                }
                EXT_BGP_NEXT_HOP_V4 => {
                    record.bgp_next_hop = Some(ExBgpNextHop {
                        ip: IpAddr::from(Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?)),
                    });
                }
                EXT_BGP_NEXT_HOP_V6 => {
                    record.bgp_next_hop = Some(ExBgpNextHop {
                        ip: IpAddr::from(Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?)),
                    });
                }
                EXT_IP_NEXT_HOP_V4 => {
                    record.ip_next_hop = Some(ExIpNextHop {
                        ip: IpAddr::from(Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?)),
                    });
                }
                EXT_IP_NEXT_HOP_V6 => {
                    record.ip_next_hop = Some(ExIpNextHop {
                        ip: IpAddr::from(Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?)),
                    });
                }
                EXT_IP_RECEIVED_V4 => {
                    record.ip_received = Some(ExIpReceived {
                        ip: IpAddr::from(Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?)),
                    });
                }
                EXT_IP_RECEIVED_V6 => {
                    record.ip_received = Some(ExIpReceived {
                        ip: IpAddr::from(Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?)),
                    });
                }
                EXT_IN_PAYLOAD => {
                    let mut payload = vec![0; record.head.header.size as usize - 4];
                    cursor.read_exact(&mut payload)?;
                    record.in_payload = Some(payload);
                }
                _ => {
                    // Skip unimplemented extensions
                    let mut buf = vec![0; size as usize - 4];
                    cursor.read_exact(&mut buf)?;
                }
            }
        }

        return Ok(record);
    }
}
