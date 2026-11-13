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
    /// The version to run (host mode), verified with the release key embedded in the agent.
    UpgradeAgent(String),
    /// A new key pair for the agent.
    RotateKey,
    /// The console key to pin from now on (`ed25519:…`), announced in an order signed by the current one.
    RotateConsoleKey(String),
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
        Some("ROTATE_KEY") => payload
            .as_object()
            .filter(|o| o.is_empty())
            .map(|_| Order::RotateKey)
            .ok_or("invalid_payload"),
        Some("ROTATE_CONSOLE_KEY") => payload
            .get("new_key")
            .and_then(Value::as_str)
            .filter(|k| {
                ConsoleKey::parse(k).is_ok() && payload.as_object().is_some_and(|o| o.len() == 1)
            })
            .map(|k| Order::RotateConsoleKey(k.to_owned()))
            .ok_or("invalid_payload"),
        Some("UPGRADE_AGENT") => payload
            .get("version")
            .and_then(Value::as_str)
            .filter(|v| {
                crate::release::is_version(v) && payload.as_object().is_some_and(|o| o.len() == 1)
            })
            .map(|v| Order::UpgradeAgent(v.to_owned()))
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

/// Forgets the orders past their keeping time, judged on the **local** clock with the largest offset allowed: no
/// console clock can make a forgotten order valid again.
pub fn prune(state: &mut State, local_now: i64) {
    state
        .seen_orders
        .retain(|_, keep_until| *keep_until + crate::client::MAX_OFFSET > local_now);
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
        assert_eq!(
            state.seen_orders.len(),
            1,
            "kept while a console offset could still make it valid"
        );
        prune(&mut state, 1_794_212_100 + 601 + crate::client::MAX_OFFSET);
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

    /// The order of the vector with another type and payload, signed again with the console seed of the vector.
    fn signed(kind: &str, payload: Value) -> Value {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let seed: [u8; 32] = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &vector["console_private_key_seed_hex"].as_str().unwrap()[i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut envelope = vector["signed_order"].clone();
        envelope["order"]["type"] = kind.into();
        envelope["order"]["payload"] = payload;
        envelope["order"]["order_id"] = format!(
            "019a6b2e-7c40-7d3e-9f1a-{:012x}",
            jcs::canonical(&envelope["order"]).len()
        )
        .into();
        let signature =
            SigningKey::from_bytes(&seed).sign(jcs::canonical(&envelope["order"]).as_bytes());
        envelope["signature"]["value"] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signature.to_bytes())
            .into();
        envelope
    }

    #[test]
    fn reads_an_upgrade_order() {
        let (_, console, mut state, now) = setup();
        let mut outcome = |payload: Value| {
            check(&signed("UPGRADE_AGENT", payload), &console, &mut state, now).outcome
        };
        assert_eq!(
            outcome(serde_json::json!({"version": "0.2.0"})),
            Ok(Order::UpgradeAgent("0.2.0".into()))
        );
        for payload in [
            serde_json::json!({"version": "latest"}),
            serde_json::json!({"version": 2}),
            serde_json::json!({}),
            serde_json::json!({"version": "0.3.0", "url": "https://elsewhere"}),
            serde_json::json!("0.3.1"),
        ] {
            assert_eq!(
                outcome(payload.clone()),
                Err("invalid_payload"),
                "{payload}"
            );
        }
        assert_eq!(
            check(
                &signed("ROTATE_EVERYTHING", serde_json::json!({})),
                &console,
                &mut state,
                now
            )
            .outcome,
            Err("unknown_type")
        );
    }

    #[test]
    fn reads_the_rotation_orders() {
        let (_, console, mut state, now) = setup();
        let mut outcome = |kind: &str, payload: Value| {
            check(&signed(kind, payload), &console, &mut state, now).outcome
        };
        assert_eq!(
            outcome("ROTATE_KEY", serde_json::json!({})),
            Ok(Order::RotateKey)
        );
        assert_eq!(
            outcome("ROTATE_KEY", serde_json::json!({"seed": "x"})),
            Err("invalid_payload")
        );
        let key = "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        assert_eq!(
            outcome("ROTATE_CONSOLE_KEY", serde_json::json!({"new_key": key})),
            Ok(Order::RotateConsoleKey(key.into()))
        );
        for payload in [
            serde_json::json!({"new_key": "ed25519:short"}),
            serde_json::json!({}),
            serde_json::json!({"new_key": key, "also": 1}),
        ] {
            assert_eq!(
                outcome("ROTATE_CONSOLE_KEY", payload.clone()),
                Err("invalid_payload"),
                "{payload}"
            );
        }
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
