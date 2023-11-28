use crate::NfFileRecordHeader;
use byteorder::{LittleEndian, ReadBytesExt};
use crate::error::NfdumpError;

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
) -> Result<ExtensionMap, NfdumpError> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let map_id = cursor.read_u16::<LittleEndian>()?;
    let extension_size = cursor.read_u16::<LittleEndian>()?;

    let mut ex_id: Vec<u16> = Vec::new();

    while let Ok(id) = cursor.read_u16::<LittleEndian>() {
        if id == 0 {
            continue;
        }
        ex_id.push(id);
    }

    Ok(ExtensionMap {
        header,
        map_id,
        extension_size,
        ex_id,
    })
}
