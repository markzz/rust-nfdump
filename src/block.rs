#[allow(dead_code)]
pub(crate) struct DataBlockHeader {
    pub(crate) num_records: u32,
    pub(crate) size: u32,
    pub(crate) id: u16,
    pub(crate) flags: u16,
    pub(crate) record_num: u32,
    pub(crate) block_num: u32,
}