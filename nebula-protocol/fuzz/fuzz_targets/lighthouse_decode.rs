#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = nebula_protocol::wire::NebulaMeta::decode(data);
});
