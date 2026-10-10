// SPDX-License-Identifier: Apache-2.0

//! Builds synthetic package containers for tests.
//!
//! Nothing here is real protocol data: component contents are placeholders,
//! which is enough for the container checks (they commit to content without
//! interpreting it). Shared with the CLI's tests by path.
#![allow(dead_code, unreachable_pub)]

use verified_canonical::{Limits, Object, Value, parse};

pub const PATHS: [&str; 6] = [
    "claim.json",
    "contract.json",
    "decision.json",
    "evidence/bodies.json",
    "evidence/statements.json",
    "inputs.json",
];

pub fn json(text: &str) -> Value {
    parse(text.as_bytes(), &Limits::DEFAULT).expect("test JSON parses")
}

pub fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Object>(),
    )
}

pub fn string(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

pub fn hash(value: &Value) -> Value {
    object([
        ("algorithm", string("sha-256")),
        ("hex", string(value.digest().to_hex())),
    ])
}

/// A package under construction. Every field is free to be made wrong.
#[derive(Clone)]
pub struct Draft {
    pub protocol: Value,
    pub package_version: Value,
    pub canonical_version: Value,
    /// `(path, content)` as carried in `files`.
    pub files: Vec<(Value, Value)>,
    /// `(path, hash)` as listed in the manifest; `None` derives them from `files`.
    pub manifest_files: Option<Vec<(Value, Value)>>,
    /// `None` derives the commitment from the manifest.
    pub package_commitment: Option<Value>,
    /// `None` derives the identifier from the manifest.
    pub package_id: Option<Value>,
    pub signatures: Value,
}

impl Draft {
    /// A package that passes every container check.
    pub fn consistent(protocol: &str) -> Self {
        Self {
            protocol: string(protocol),
            package_version: Value::Integer(2.into()),
            canonical_version: string("verified-json-v1"),
            files: PATHS
                .iter()
                .map(|path| (string(*path), object([("synthetic", string(*path))])))
                .collect(),
            manifest_files: None,
            package_commitment: None,
            package_id: None,
            signatures: Value::Array(Vec::new()),
        }
    }

    pub fn manifest(&self) -> Value {
        let listed = self.manifest_files.clone().unwrap_or_else(|| {
            self.files
                .iter()
                .map(|(path, content)| (path.clone(), hash(content)))
                .collect()
        });
        object([
            ("canonicalVersion", self.canonical_version.clone()),
            (
                "files",
                Value::Array(
                    listed
                        .into_iter()
                        .map(|(path, hash)| object([("hash", hash), ("path", path)]))
                        .collect(),
                ),
            ),
            ("packageVersion", self.package_version.clone()),
            ("protocol", self.protocol.clone()),
        ])
    }

    pub fn value(&self) -> Value {
        let manifest = self.manifest();
        let commitment = manifest.digest().to_hex();
        object([
            (
                "files",
                Value::Array(
                    self.files
                        .iter()
                        .map(|(path, content)| {
                            object([("content", content.clone()), ("path", path.clone())])
                        })
                        .collect(),
                ),
            ),
            (
                "packageCommitment",
                self.package_commitment
                    .clone()
                    .unwrap_or_else(|| hash(&manifest)),
            ),
            (
                "packageId",
                self.package_id
                    .clone()
                    .unwrap_or_else(|| string(format!("wvp:sha-256:{commitment}"))),
            ),
            ("signatures", self.signatures.clone()),
            ("manifest", manifest),
        ])
    }

    /// The package text, canonical.
    pub fn text(&self) -> String {
        self.value().to_canonical_string()
    }
}

// ---- signed, well-formed synthetic packages -------------------------------
//
// Everything below is invented for these tests: the tenants, systems, keys
// and records name nothing real. The keys are derived from fixed one-byte
// seeds and must never be used for anything else.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};

pub const TENANT: &str = "tenant-test";
pub const STATEMENT_DOMAIN: &str = "verified:evidence-statement:v1\n";

pub fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

pub fn wrapped(value: impl Into<String>) -> Value {
    object([("value", string(value))])
}

pub fn list(items: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(items.into_iter().collect())
}

pub fn unit(case: &str) -> Value {
    object([(case, object([]))])
}

/// `value` with the member at `path` replaced. Path segments are object keys
/// or array indices. With `None`, the member is removed.
pub fn replaced(value: &Value, path: &[&str], new: Option<Value>) -> Value {
    let Some((head, rest)) = path.split_first() else {
        return new.expect("the root cannot be removed");
    };
    match value {
        Value::Object(members) => {
            let mut out: Object = members
                .iter()
                .filter(|(key, _)| key != head)
                .map(|(k, v)| (k.to_owned(), v.clone()))
                .collect();
            let old = members.get(head).cloned().unwrap_or(Value::Null);
            if !rest.is_empty() || new.is_some() {
                out.insert(*head, replaced(&old, rest, new));
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let index: usize = head.parse().expect("an array index");
            let mut out = items.clone();
            if rest.is_empty() && new.is_none() {
                out.remove(index);
            } else {
                out[index] = replaced(&items[index], rest, new);
            }
            Value::Array(out)
        }
        other => panic!("cannot descend into {other:?} at {head}"),
    }
}

/// A test signing key and the registry record a relying party would hold
/// for it.
#[derive(Clone, Debug)]
pub struct Key {
    pub id: &'static str,
    pub seed: u8,
    pub issuer: String,
    pub tenant: &'static str,
    pub sources: Vec<&'static str>,
    pub valid_from: &'static str,
    pub valid_until: Option<&'static str>,
    pub revoked_at: Option<&'static str>,
    pub algorithm: &'static str,
}

impl Key {
    pub fn new(id: &'static str, seed: u8, sources: &[&'static str]) -> Self {
        Self {
            id,
            seed,
            issuer: uuid(0x100 + u32::from(seed)),
            tenant: TENANT,
            sources: sources.to_vec(),
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: None,
            revoked_at: None,
            algorithm: "Ed25519",
        }
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&[self.seed; 32])
    }

    /// Base64 of the DER `SubjectPublicKeyInfo`.
    pub fn public_key(&self) -> String {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(self.signing().verifying_key().as_bytes());
        STANDARD.encode(der)
    }

    /// `{ scheme, keyId, encoded }` over `domain` followed by the canonical
    /// text of `value`.
    pub fn sign(&self, domain: &str, value: &Value) -> Value {
        let mut message = domain.as_bytes().to_vec();
        message.extend_from_slice(value.to_canonical_string().as_bytes());
        object([
            ("scheme", string("Ed25519")),
            ("keyId", string(self.id)),
            (
                "encoded",
                string(STANDARD.encode(self.signing().sign(&message).to_bytes())),
            ),
        ])
    }

    pub fn record(&self) -> Value {
        let time = |t: Option<&str>| t.map_or(Value::Null, wrapped);
        object([
            ("algorithm", string(self.algorithm)),
            ("issuer", wrapped(self.issuer.clone())),
            ("keyId", string(self.id)),
            ("publicKey", string(self.public_key())),
            ("revokedAt", time(self.revoked_at)),
            ("sources", list(self.sources.iter().map(|s| string(*s)))),
            ("tenant", wrapped(self.tenant)),
            ("validFrom", wrapped(self.valid_from)),
            ("validUntil", time(self.valid_until)),
        ])
    }
}

pub fn registry(keys: &[&Key]) -> Value {
    object([("keys", list(keys.iter().map(|k| k.record())))])
}

/// One piece of evidence: what a statement says and the body it commits to.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub tenant: String,
    pub kind: &'static str,
    pub subject: Value,
    pub source: String,
    pub observed_at: String,
    pub protocol: String,
    pub body: Value,
    /// `None` commits to `body`.
    pub payload: Option<Value>,
    pub key: Key,
}

impl Item {
    pub fn new(n: u32, key: &Key, source: &str, body: Value) -> Self {
        Self {
            id: uuid(n),
            tenant: TENANT.to_owned(),
            kind: "Event",
            subject: subject(),
            source: source.to_owned(),
            observed_at: "2026-03-01T10:00:00Z".to_owned(),
            protocol: "verified-evidence-statement-v1".to_owned(),
            body,
            payload: None,
            key: key.clone(),
        }
    }

    pub fn statement(&self) -> Value {
        object([
            ("chain", Value::Null),
            ("id", wrapped(self.id.clone())),
            ("issuer", wrapped(self.key.issuer.clone())),
            ("kind", unit(self.kind)),
            ("observedAt", wrapped(self.observed_at.clone())),
            (
                "payload",
                self.payload.clone().unwrap_or_else(|| hash(&self.body)),
            ),
            ("protocol", string(self.protocol.clone())),
            (
                "source",
                object([
                    ("observationId", string(format!("obs-{}", self.id))),
                    ("system", string(self.source.clone())),
                ]),
            ),
            ("subject", self.subject.clone()),
            ("tenant", wrapped(self.tenant.clone())),
        ])
    }

    pub fn signed(&self) -> Value {
        let statement = self.statement();
        object([
            ("signature", self.key.sign(STATEMENT_DOMAIN, &statement)),
            ("statement", statement),
        ])
    }
}

pub fn subject() -> Value {
    object([
        ("system", string("erp")),
        ("kind", string("order")),
        ("key", string("SO-1")),
    ])
}

/// The parts of a package before it is assembled. Change a part and the
/// assembled package stays internally consistent (digests, commitments and
/// signatures follow), so a test isolates exactly one inconsistency.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub protocol: &'static str,
    pub claim: Value,
    pub contract: Value,
    pub items: Vec<Item>,
    pub inputs: Value,
    /// The evaluator's outcome as the issuer recorded it, stated by hand in
    /// each test: `decision` plus the version's own members.
    pub outcome: Value,
    pub evaluator: Value,
    pub decision_protocol: &'static str,
    /// Keys that sign the decision as its issuer.
    pub issuers: Vec<Key>,
}

pub fn evidence_key() -> Key {
    Key::new("test-erp-gateway", 1, &["erp"])
}

pub fn issuer_key() -> Key {
    Key::new("test-decision-issuer", 2, &["wvp-decision"])
}

fn inputs() -> Value {
    object([
        ("tenant", wrapped(TENANT)),
        ("packageId", wrapped(uuid(0x900))),
        ("ingestedAt", wrapped("2026-03-01T11:00:00Z")),
        ("assembledAt", wrapped("2026-03-01T12:00:00Z")),
        ("evaluatedAt", wrapped("2026-03-01T13:00:00Z")),
    ])
}

impl Scenario {
    /// A `wvp-0.2` package whose one requirement, "the invoice is posted",
    /// is established by one signed record from the accepted source.
    pub fn posted() -> Self {
        let contract = json(
            r#"{
              "language": "work-contract-1",
              "identity": {"id": "posting-test", "version": "1.0.0"},
              "inputs": {"invoice": {"type": "text"}},
              "kinds": {"posting": {"key": ["document"], "fields": {
                "document": {"type": "text"}, "invoice": {"type": "text"}}}},
              "evidence": {"conflicts": "unknown", "sources": {"posting": ["erp"]}},
              "policy": {},
              "evaluation": {"semantics": "kleene-1"},
              "requires": [{"id": "POSTED", "predicate": {
                "exists": "p", "in": "posting", "where": {"cmp": "eq",
                  "left": {"var": "p", "field": "invoice"}, "right": {"input": "invoice"}}}}]
            }"#,
        );
        let record = json(
            r#"{"record": {"kind": "posting", "fields": {"document": "D-1", "invoice": "INV-1"}}}"#,
        );
        let items = vec![Item::new(1, &evidence_key(), "erp", record)];
        Self {
            protocol: "wvp-0.2",
            claim: object([
                ("id", wrapped(uuid(0x500))),
                ("tenant", wrapped(TENANT)),
                ("contract", hash(&contract)),
                ("inputs", json(r#"{"invoice": "INV-1"}"#)),
                ("claimant", wrapped(uuid(0x600))),
                (
                    "evidence",
                    list(items.iter().map(|i| wrapped(i.id.clone()))),
                ),
                ("submittedAt", wrapped("2026-03-01T12:30:00Z")),
            ]),
            contract,
            items,
            inputs: inputs(),
            outcome: json(
                r#"{"decision": "SUPPORTED", "requirements": [{"id": "POSTED", "value": "TRUE"}],
                    "ignored": [], "conflicts": []}"#,
            ),
            evaluator: json(r#"{"name": "work-contract", "specification": "1"}"#),
            decision_protocol: "wvp-0.2",
            issuers: Vec::new(),
        }
    }

    /// A `wvp-0.1` package: an order claimed shipped, with one signed
    /// transition from `Approved` to `Shipped`.
    pub fn shipped() -> Self {
        let at = "2026-03-01T10:00:00Z";
        let transition = object([(
            "StateTransition",
            object([
                ("subject", subject()),
                ("from", unit("Approved")),
                ("to", unit("Shipped")),
                ("at", wrapped(at)),
            ]),
        )]);
        let mut item = Item::new(1, &evidence_key(), "erp", transition);
        item.kind = "StateTransition";
        let outcome = object([("OrderReached", object([("state", unit("Shipped"))]))]);
        let version = json(r#"{"major": 1, "minor": 0, "patch": 0}"#);
        let contract = object([
            ("id", wrapped(uuid(0x700))),
            ("version", version.clone()),
            ("workType", unit("OrderFulfillment")),
            ("subject", subject()),
            ("expectedOutcome", outcome.clone()),
            (
                "policy",
                object([
                    ("id", wrapped(uuid(0x701))),
                    ("version", version),
                    (
                        "rule",
                        object([
                            ("allowedFrom", list([unit("Approved")])),
                            ("to", unit("Shipped")),
                        ]),
                    ),
                    ("requiredEvidence", list([unit("StateTransition")])),
                ]),
            ),
            ("parties", list([wrapped(uuid(0x600))])),
            (
                "validity",
                object([
                    ("from", wrapped("2026-01-01T00:00:00Z")),
                    ("until", Value::Null),
                ]),
            ),
        ]);
        let claim = object([
            ("id", wrapped(uuid(0x500))),
            ("contractId", wrapped(uuid(0x700))),
            ("claimant", wrapped(uuid(0x600))),
            ("subject", subject()),
            ("outcome", outcome),
            ("evidence", list([wrapped(item.id.clone())])),
            ("occurredAt", wrapped(at)),
            ("submittedAt", wrapped("2026-03-01T12:30:00Z")),
            (
                "provenance",
                object([
                    (
                        "source",
                        object([
                            ("system", string("erp")),
                            ("observationId", string("claim-1")),
                        ]),
                    ),
                    ("witness", wrapped(uuid(0x600))),
                    ("trust", unit("Unauthenticated")),
                    ("observedAt", wrapped(at)),
                    ("ingestedAt", wrapped("2026-03-01T11:00:00Z")),
                    ("transformations", list([])),
                    ("causedBy", list([])),
                ]),
            ),
            ("supersedes", Value::Null),
        ]);
        let id = wrapped(item.id.clone());
        Self {
            protocol: "wvp-0.1",
            claim,
            contract,
            items: vec![item],
            inputs: inputs(),
            outcome: object([
                ("decision", string("SUPPORTED")),
                (
                    "conditions",
                    list([
                        condition("CONTRADICTING_TRANSITION", false, []),
                        condition("OUTCOME_IS_TARGET", true, []),
                        condition("REQUIRED_EVIDENCE", true, []),
                        condition("SUPPORTING_TRANSITION", true, [id]),
                    ]),
                ),
            ]),
            evaluator: json(r#"{"name": "order-transition", "specification": "1"}"#),
            decision_protocol: "wvp-0.1",
            issuers: Vec::new(),
        }
    }

    fn sorted_items(&self) -> Vec<&Item> {
        let mut items: Vec<&Item> = self.items.iter().collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        items
    }

    /// The decision's commitment to the evidence, computed the way each
    /// protocol version defines it.
    fn evidence_commitment(&self) -> Value {
        let items = self.sorted_items();
        if self.protocol == "wvp-0.2" {
            return hash(&list(items.iter().map(|i| hash(&i.statement()))));
        }
        let member = |value: &Value, name: &str| {
            value
                .as_object()
                .and_then(|o| o.get(name))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let manifest_items = items.iter().map(|item| {
            let statement = item.statement();
            object([
                ("id", member(&statement, "id")),
                ("kind", member(&statement, "kind")),
                ("subject", member(&statement, "subject")),
                ("payloadHash", member(&statement, "payload")),
                (
                    "provenance",
                    object([
                        ("source", member(&statement, "source")),
                        ("witness", member(&statement, "issuer")),
                        ("trust", unit("Signed")),
                        ("observedAt", member(&statement, "observedAt")),
                        ("ingestedAt", member(&self.inputs, "ingestedAt")),
                        (
                            "transformations",
                            list([object([
                                ("name", string("verified-evidence-statement")),
                                ("version", json(r#"{"major": 1, "minor": 0, "patch": 0}"#)),
                                ("inputHashes", list([hash(&statement)])),
                            ])]),
                        ),
                        ("causedBy", list([])),
                    ]),
                ),
            ])
        });
        hash(&object([
            ("version", string("verified-evidence-manifest-v1")),
            ("id", member(&self.inputs, "packageId")),
            ("claimId", member(&self.claim, "id")),
            ("items", list(manifest_items)),
            ("assembledAt", member(&self.inputs, "assembledAt")),
        ]))
    }

    pub fn decision(&self) -> Value {
        let mut decision = match &self.outcome {
            Value::Object(members) => members.clone(),
            other => panic!("an outcome is an object, not {other:?}"),
        };
        decision.insert("protocol", string(self.decision_protocol));
        decision.insert("evaluator", self.evaluator.clone());
        decision.insert(
            "commitments",
            object([
                ("claim", hash(&self.claim)),
                ("contract", hash(&self.contract)),
                ("evidence", self.evidence_commitment()),
                ("inputs", hash(&self.inputs)),
            ]),
        );
        Value::Object(decision)
    }

    /// The assembled package, still open to container-level changes.
    pub fn draft(&self) -> Draft {
        let items = self.sorted_items();
        let decision = self.decision();
        let domain = format!("verified:wvp-decision:v{}\n", &self.protocol[4..]);
        let contents = [
            self.claim.clone(),
            self.contract.clone(),
            decision.clone(),
            list(
                items
                    .iter()
                    .map(|i| object([("id", wrapped(i.id.clone())), ("body", i.body.clone())])),
            ),
            list(items.iter().map(|i| i.signed())),
            self.inputs.clone(),
        ];
        Draft {
            files: PATHS.iter().map(|p| string(*p)).zip(contents).collect(),
            signatures: list(self.issuers.iter().map(|key| key.sign(&domain, &decision))),
            ..Draft::consistent(self.protocol)
        }
    }

    pub fn text(&self) -> String {
        self.draft().text()
    }
}

pub fn condition<const N: usize>(id: &str, holds: bool, evidence: [Value; N]) -> Value {
    object([
        ("id", string(id)),
        ("holds", Value::Bool(holds)),
        ("evidence", list(evidence)),
    ])
}
