// TODO(next-phase): delete
#[derive(Default)]
pub struct ReceiveWindow {}

impl ReceiveWindow {
    pub fn insert(&mut self, _seq: u64, _payload: Vec<u8>) -> Vec<Vec<u8>> {
        Vec::new()
    }
}
