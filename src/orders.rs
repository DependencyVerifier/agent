//! Orders (protocol §7): checked in the order of §7.2, then executed one at a time. The catalogue is closed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::jcs;
use crate::keys::ConsoleKey;
use crate::state::{CollectConfig, State};

/// What an accepted order asks for.
#[derive(Debug, PartialEq)]
pub enum Order {
    ScanNow,
    SetConfig(CollectConfig),
}

pub struct Checked {
    pub order_id: String,
    pub outcome: Result<Order, &'static str>,
}

const MAX_VALIDITY: i64 = 15 * 60;
const TOLERANCE: i64 = 60;
const MAX_PATHS: usize = 200;

/// §7.2, in order: signature with the pinned key, agent, validity window, replay, catalogue and payload. A checked
/// order (accepted or not) enters the anti-replay store.
pub fn check(envelope: &Value, console: &ConsoleKey, state: &mut State, now: i64) -> Checked {
    let order = envelope.get("order").cloned().unwrap_or(Value::Null);
    let order_id = order
        .get("order_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let outcome = verify(envelope, &order, console, state, now);
    let expires = order
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(crate::time::parse_rfc3339)
        .unwrap_or(now);
    if outcome != Err("replayed") {
        state
            .seen_orders
            .insert(order_id.clone(), expires.max(now) + 600);
    }
    Checked { order_id, outcome }
}

fn verify(
    envelope: &Value,
    order: &Value,
    console: &ConsoleKey,
    state: &State,
    now: i64,
) -> Result<Order, &'static str> {
    let signature = envelope.get("signature").unwrap_or(&Value::Null);
    let value = signature
        .get("value")
        .and_then(Value::as_str)
        .and_then(|v| URL_SAFE_NO_PAD.decode(v.trim_end_matches('=')).ok());
    let signed = signature.get("alg").and_then(Value::as_str) == Some("ed25519")
        && signature.get("key_id").and_then(Value::as_str) == Some(console.fingerprint().as_str())
        && order.is_object()
        && value.is_some_and(|v| console.verify(jcs::canonical(order).as_bytes(), &v));
    if !signed {
        return Err("bad_signature");
    }
    if order.get("agent_id").and_then(Value::as_str) != state.agent_id.as_deref() {
        return Err("wrong_agent");
    }
    let time = |field: &str| {
        order
            .get(field)
            .and_then(Value::as_str)
            .and_then(crate::time::parse_rfc3339)
    };
    let (Some(issued), Some(not_before), Some(expires)) =
        (time("issued_at"), time("not_before"), time("expires_at"))
    else {
        return Err("expired");
    };
    if now + TOLERANCE < not_before || now - TOLERANCE > expires || expires - issued > MAX_VALIDITY
    {
        return Err("expired");
    }
    let id = order.get("order_id").and_then(Value::as_str).unwrap_or("");
    if state.seen_orders.contains_key(id) {
        return Err("replayed");
    }
    let payload = order.get("payload").unwrap_or(&Value::Null);
    match order.get("type").and_then(Value::as_str) {
        Some("SCAN_NOW") => payload
            .as_object()
            .map(|_| Order::ScanNow)
            .ok_or("invalid_payload"),
        Some("SET_CONFIG") => set_config(payload)
            .map(Order::SetConfig)
            .ok_or("invalid_payload"),
        _ => Err("unknown_type"),
    }
}

fn set_config(payload: &Value) -> Option<CollectConfig> {
    let version = payload.get("config_version")?.as_u64()?;
    let interval = payload.get("scan_interval_minutes")?.as_u64()?;
    if !(5..=10_080).contains(&interval) {
        return None;
    }
    let paths = |field: &str| -> Option<Vec<String>> {
        let Some(value) = payload.get(field) else {
            return Some(vec![]);
        };
        let items = value.as_array()?;
        if items.len() > MAX_PATHS {
            return None;
        }
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|p| p.starts_with('/') && p.len() <= 4096)
                    .map(str::to_owned)
            })
            .collect()
    };
    Some(CollectConfig {
        version,
        scan_interval_minutes: interval,
        discovery_roots: paths("discovery_roots")?,
        declared_paths: paths("declared_paths")?,
        exclusions: paths("exclusions")?,
    })
}

/// Forgets the orders past their keeping time.
pub fn prune(state: &mut State, now: i64) {
    state.seen_orders.retain(|_, keep_until| *keep_until > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = include_str!("../tests/fixtures/order-signature.json");

    fn setup() -> (Value, ConsoleKey, State, i64) {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let console = ConsoleKey::parse(vector["console_public_key"].as_str().unwrap()).unwrap();
        let state = State {
            agent_id: Some("019a6b2c-1f00-7a11-8b22-3c44d55e6f01".into()),
            ..State::default()
        };
        (
            vector["signed_order"].clone(),
            console,
            state,
            1_794_211_260,
        )
    }

    #[test]
    fn accepts_the_signed_order_of_the_vector() {
        let (envelope, console, mut state, now) = setup();
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        assert_eq!(
            jcs::canonical(&envelope["order"]),
            vector["canonical_order"].as_str().unwrap()
        );

        let checked = check(&envelope, &console, &mut state, now);
        assert_eq!(checked.order_id, "019a6b2e-7c40-7d3e-9f1a-2b3c4d5e6f70");
        assert_eq!(
            checked.outcome,
            Ok(Order::SetConfig(CollectConfig {
                version: 3,
                scan_interval_minutes: 360,
                discovery_roots: vec!["/var/www".into(), "/srv".into()],
                declared_paths: vec!["/opt/legacy-app".into()],
                exclusions: vec!["/var/www/**/node_modules/.cache".into()],
            }))
        );
        assert_eq!(
            check(&envelope, &console, &mut state, now).outcome,
            Err("replayed")
        );
        prune(&mut state, 1_794_212_100 + 601);
        assert!(state.seen_orders.is_empty());
    }

    #[test]
    fn rejects_in_the_order_of_the_protocol() {
        let (envelope, console, state, now) = setup();
        let reject = |envelope: &Value, state: &State, now: i64| {
            check(
                envelope,
                &console,
                &mut State {
                    seen_orders: state.seen_orders.clone(),
                    agent_id: state.agent_id.clone(),
                    ..State::default()
                },
                now,
            )
            .outcome
        };

        let mut tampered = envelope.clone();
        tampered["order"]["payload"]["scan_interval_minutes"] = 5.into();
        assert_eq!(reject(&tampered, &state, now), Err("bad_signature"));
        let other_key =
            ConsoleKey::parse("ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=").unwrap();
        assert_eq!(
            check(&envelope, &other_key, &mut State::default(), now).outcome,
            Err("bad_signature")
        );
        let stranger = State {
            agent_id: Some("someone-else".into()),
            ..State::default()
        };
        assert_eq!(reject(&envelope, &stranger, now), Err("wrong_agent"));
        assert_eq!(
            reject(&envelope, &state, 1_794_211_200 - 61),
            Err("expired")
        );
        assert_eq!(
            reject(&envelope, &state, 1_794_212_100 + 61),
            Err("expired")
        );
        assert!(
            reject(&envelope, &state, 1_794_212_100 + 60).is_ok(),
            "within the tolerance"
        );
    }

    #[test]
    fn reads_the_payloads_strictly() {
        assert!(
            set_config(&serde_json::json!({"config_version": 1, "scan_interval_minutes": 4}))
                .is_none()
        );
        assert!(set_config(&serde_json::json!({"config_version": 1, "scan_interval_minutes": 60, "declared_paths": ["relative"]})).is_none());
        let minimal =
            set_config(&serde_json::json!({"config_version": 2, "scan_interval_minutes": 60}))
                .unwrap();
        assert!(minimal.discovery_roots.is_empty() && minimal.declared_paths.is_empty());
    }
}
