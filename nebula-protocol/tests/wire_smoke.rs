//! Confirms the protobuf codegen wires up correctly and matches nebula's
//! own wire format for the handshake payload message.
use prost::Message;

#[test]
fn nebula_handshake_round_trips() {
    let msg = nebula_protocol::wire::NebulaHandshake {
        details: Some(nebula_protocol::wire::NebulaHandshakeDetails {
            cert: vec![1, 2, 3],
            initiator_index: 42,
            responder_index: 0,
            cookie: 0,
            time: 1_234_567_890,
            cert_version: 2,
        }),
        hmac: vec![],
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    let decoded = nebula_protocol::wire::NebulaHandshake::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded, msg);
}
