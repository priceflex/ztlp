// TODO(next-phase): delete
use tokio::sync::mpsc;
use std::sync::Arc;
use crate::transport::TransportNode;
pub struct SendController {}
impl SendController {
    pub fn new(_transport: Arc<TransportNode>, _session_id: crate::packet::SessionId, _peer_addr: std::net::SocketAddr, _ack_rx: mpsc::UnboundedReceiver<u64>) -> Self { Self {} }
    pub fn enqueue_priority(&mut self, _frame: Vec<u8>) {}
    pub fn enqueue(&mut self, _frame: Vec<u8>) {}
    pub fn process_acks(&mut self) {}
    pub fn purge_stream(&mut self, _stream_id: u32) {}
    pub async fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
    pub async fn check_retransmit(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}
