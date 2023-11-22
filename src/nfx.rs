use crate::NfFileRecordHeader;
use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Debug)]
pub struct ExtensionMap {
    pub header: NfFileRecordHeader,
    pub map_id: u16,
    pub extension_size: u16,
    pub ex_id: Vec<u16>,
}

pub fn read_extension_map(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Option<ExtensionMap> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let map_id = cursor.read_u16::<LittleEndian>().ok().unwrap();
    let extension_size = cursor.read_u16::<LittleEndian>().ok().unwrap();

    let mut ex_id: Vec<u16> = Vec::new();

    while let Some(id) = cursor.read_u16::<LittleEndian>().ok() {
        if id == 0 {
            continue;
        }
        ex_id.push(id);
    }

    Some(ExtensionMap {
        header,
        map_id,
        extension_size,
        ex_id,
    })
}
