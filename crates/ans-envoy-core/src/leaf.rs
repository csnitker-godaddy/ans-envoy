//! Reading the sealed leaf a SCITT receipt carries.
//!
//! ANS-6 §4.3 attaches the JCS-canonicalized sealed leaf to the receipt, so a
//! verifier reconstructs the leaf hash "from the receipt alone, with no side
//! channel to the sealed record". That also means the leaf is where the agent's
//! own claimed identity lives, and §6.3 binds a Method-A client certificate
//! against it.
//!
//! Only the identity fields are read. The envelope is a V2 TL envelope
//! (§4.1) and the paths are `.payload.producer.event.{ansId, ansName,
//! agent.host}`; a flat form is accepted as a fallback because the spec's own
//! path table and the reference implementation have moved during the draft, and
//! failing to find a field is handled by the caller rather than here.

use serde::Deserialize;

/// Identity fields read out of a receipt's sealed leaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafIdentity {
    /// The agent's UUID, as written in the leaf.
    pub ans_id: Option<String>,
    /// The agent's full `ans://` name, version segment included.
    pub ans_name: Option<String>,
    /// The registered agent host — what §6.3 compares a client certificate's
    /// DNS SAN against.
    pub agent_host: Option<String>,
}

impl LeafIdentity {
    /// True when the leaf names no agent at all.
    ///
    /// §7.5.3: "A leaf naming no agent at all is invalid." The same reasoning
    /// applies to Method A: a leaf that identifies nothing cannot corroborate a
    /// certificate.
    pub fn names_nothing(&self) -> bool {
        self.ans_id.is_none() && self.ans_name.is_none()
    }
}

/// Errors from reading a leaf.
#[derive(Debug, thiserror::Error)]
pub enum LeafError {
    /// The leaf bytes were not decodable JSON.
    #[error("receipt leaf event is not decodable JSON: {0}")]
    NotJson(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct Envelope {
    payload: Option<EnvelopePayload>,
    #[serde(rename = "ansId")]
    ans_id: Option<String>,
    #[serde(rename = "ansName")]
    ans_name: Option<String>,
    agent: Option<Agent>,
}

#[derive(Debug, Deserialize)]
struct EnvelopePayload {
    producer: Option<Producer>,
}

#[derive(Debug, Deserialize)]
struct Producer {
    event: Option<LeafEvent>,
}

#[derive(Debug, Deserialize)]
struct LeafEvent {
    #[serde(rename = "ansId")]
    ans_id: Option<String>,
    #[serde(rename = "ansName")]
    ans_name: Option<String>,
    agent: Option<Agent>,
}

#[derive(Debug, Deserialize)]
struct Agent {
    host: Option<String>,
}

/// Read the identity fields from a receipt's sealed leaf bytes.
pub fn parse_leaf_identity(event_bytes: &[u8]) -> Result<LeafIdentity, LeafError> {
    let envelope: Envelope = serde_json::from_slice(event_bytes)?;

    if let Some(event) = envelope
        .payload
        .as_ref()
        .and_then(|p| p.producer.as_ref())
        .and_then(|p| p.event.as_ref())
    {
        return Ok(LeafIdentity {
            ans_id: event.ans_id.clone(),
            ans_name: event.ans_name.clone(),
            agent_host: event.agent.as_ref().and_then(|a| a.host.clone()),
        });
    }

    Ok(LeafIdentity {
        ans_id: envelope.ans_id,
        ans_name: envelope.ans_name,
        agent_host: envelope.agent.and_then(|a| a.host),
    })
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_v2_envelope_path() {
        let leaf = br#"{
            "schemaVersion": "V2",
            "payload": {
                "producer": {
                    "event": {
                        "ansId": "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07",
                        "ansName": "ans://v1.0.0.agent.example.com",
                        "agent": { "host": "agent.example.com", "version": "v1.0.0" }
                    }
                }
            }
        }"#;
        let id = parse_leaf_identity(leaf).unwrap();
        assert_eq!(
            id.ans_name.as_deref(),
            Some("ans://v1.0.0.agent.example.com")
        );
        assert_eq!(id.agent_host.as_deref(), Some("agent.example.com"));
        assert_eq!(
            id.ans_id.as_deref(),
            Some("7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07")
        );
        assert!(!id.names_nothing());
    }

    #[test]
    fn falls_back_to_a_flat_leaf() {
        let leaf = br#"{
            "ansId": "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07",
            "ansName": "ans://v2.0.0.flat.example.com",
            "agent": { "host": "flat.example.com" }
        }"#;
        let id = parse_leaf_identity(leaf).unwrap();
        assert_eq!(
            id.ans_name.as_deref(),
            Some("ans://v2.0.0.flat.example.com")
        );
        assert_eq!(id.agent_host.as_deref(), Some("flat.example.com"));
    }

    #[test]
    fn a_leaf_naming_nothing_is_detectable() {
        let id = parse_leaf_identity(br#"{"schemaVersion":"V2"}"#).unwrap();
        assert!(id.names_nothing());
        assert!(id.agent_host.is_none());
    }

    #[test]
    fn the_nested_path_wins_over_flat_fields() {
        // A leaf carrying both must not let an attacker-chosen top-level field
        // shadow the sealed event.
        let leaf = br#"{
            "ansName": "ans://v9.9.9.attacker.example.com",
            "payload": { "producer": { "event": {
                "ansName": "ans://v1.0.0.real.example.com",
                "agent": { "host": "real.example.com" }
            } } }
        }"#;
        let id = parse_leaf_identity(leaf).unwrap();
        assert_eq!(
            id.ans_name.as_deref(),
            Some("ans://v1.0.0.real.example.com")
        );
    }

    #[test]
    fn non_json_is_an_error_not_an_empty_identity() {
        assert!(parse_leaf_identity(b"\x00\x01not json").is_err());
    }

    #[test]
    fn unknown_leaf_fields_are_tolerated() {
        // The leaf schema is still moving in the draft; an added field must not
        // turn a valid receipt into a rejection.
        let leaf = br#"{
            "payload": { "producer": { "event": {
                "ansName": "ans://v1.0.0.a.example.com",
                "agent": { "host": "a.example.com" },
                "somethingNew": { "nested": true }
            } } },
            "alsoNew": 42
        }"#;
        let id = parse_leaf_identity(leaf).unwrap();
        assert_eq!(id.agent_host.as_deref(), Some("a.example.com"));
    }
}
