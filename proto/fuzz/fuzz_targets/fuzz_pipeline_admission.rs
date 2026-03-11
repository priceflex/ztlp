//! Fuzz target: three-layer admission pipeline.
//!
//! Feeds random packets through the Pipeline's three admission layers,
//! both individually and through the combined `process()` method.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ztlp_proto::identity::NodeId;
use ztlp_proto::packet::SessionId;
use ztlp_proto::pipeline::Pipeline;
use ztlp_proto::session::SessionState;

fuzz_target!(|data: &[u8]| {
    let mut pipeline = Pipeline::new();

    // Register a few sessions so some packets might pass Layer 2
    for i in 0..3u8 {
        let mut sid = [0u8; 12];
        sid[0] = i;
        let session = SessionState::new(
            SessionId(sid),
            NodeId::zero(),
            [i; 32],
            [i.wrapping_add(1); 32],
            false,
        );
        pipeline.register_session(session);
    }

    // Test individual layers
    let _ = pipeline.layer1_magic_check(data);
    let _ = pipeline.layer2_session_check(data);
    let _ = pipeline.layer3_auth_check(data);

    // Test combined pipeline
    let _ = pipeline.process(data);
    let _ = pipeline.process_from(data, Some("fuzz:0"));

    // Test with empty and minimal inputs
    let _ = pipeline.process(&[]);
    let _ = pipeline.process(&[0]);
    if data.len() >= 2 {
        let _ = pipeline.process(&data[..2]);
    }
    if data.len() >= 4 {
        let _ = pipeline.process(&data[..4]);
    }
});
