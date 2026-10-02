use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::json;
use zeropw::team::commit::new_env_id;
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{
    InProcessTransport, MembershipCheck, Session, TcpTransport, Transport,
};

fn members(records: &[DeviceRecord]) -> MembershipCheck {
    let entries: HashMap<_, _> = records
        .iter()
        .map(|r| (r.fingerprint(), r.clone()))
        .collect();
    Arc::new(move |_env, fp| entries.get(fp).cloned())
}

fn exchange(tcp: bool) {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let a_record = a.record().unwrap();
    let b_record = b.record().unwrap();
    let env = new_env_id(&a_record.fingerprint()).unwrap();
    let (tx, rx) = mpsc::channel::<Arc<dyn Session>>();
    if tcp {
        let ta = TcpTransport::new(a, members(std::slice::from_ref(&b_record)), 4);
        let tb = TcpTransport::new(b, members(std::slice::from_ref(&a_record)), 4);
        tb.listen_arc(
            "127.0.0.1:0",
            Arc::new(move |s| {
                tx.send(s).unwrap();
            }),
        )
        .unwrap();
        let outbound = ta
            .dial_session(&tb.bound_address().unwrap(), &env, None)
            .unwrap();
        let inbound = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(inbound.peer().fingerprint(), a_record.fingerprint());
        assert_eq!(outbound.peer().fingerprint(), b_record.fingerprint());
        outbound
            .send(&json!({"type":"VECTOR","vector":{"a":1}}))
            .unwrap();
        assert_eq!(
            inbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
            "VECTOR"
        );
        inbound.send(&json!({"type":"PEERS","peers":{}})).unwrap();
        assert_eq!(
            outbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
            "PEERS"
        );
        outbound.close();
        inbound.close();
        tb.shutdown();
    } else {
        let ta = InProcessTransport::new(a, members(std::slice::from_ref(&b_record)));
        let tb = InProcessTransport::new(b, members(std::slice::from_ref(&a_record)));
        tb.listen(
            "team-transport-test",
            Arc::new(move |s| {
                tx.send(s).unwrap();
            }),
        )
        .unwrap();
        let outbound = ta.dial("team-transport-test", &env, None).unwrap();
        let inbound = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(inbound.peer().fingerprint(), a_record.fingerprint());
        assert_eq!(outbound.peer().fingerprint(), b_record.fingerprint());
        outbound
            .send(&json!({"type":"VECTOR","vector":{"a":1}}))
            .unwrap();
        assert_eq!(
            inbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
            "VECTOR"
        );
        inbound.send(&json!({"type":"PEERS","peers":{}})).unwrap();
        assert_eq!(
            outbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
            "PEERS"
        );
        outbound.close();
        inbound.close();
        tb.close();
    }
}

#[test]
fn inprocess_mutual_handshake_and_messages() {
    exchange(false);
}
#[test]
fn tcp_mutual_handshake_and_messages() {
    exchange(true);
}

#[test]
fn nonmember_is_refused_without_session() {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let env = new_env_id(&a.fingerprint().unwrap()).unwrap();
    let ta = InProcessTransport::new(a, members(&[b.record().unwrap()]));
    let tb = InProcessTransport::new(b, members(&[]));
    let seen = Arc::new(Mutex::new(false));
    let seen2 = seen.clone();
    tb.listen(
        "team-nonmember-test",
        Arc::new(move |_| {
            *seen2.lock().unwrap() = true;
        }),
    )
    .unwrap();
    assert!(ta.dial("team-nonmember-test", &env, None).is_err());
    assert!(!*seen.lock().unwrap());
    tb.close();
}
