//! The WVP conformance corpus.
//!
//! The corpus is not part of this repository until its publication is
//! approved; see `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR`
//! at a directory holding `wvp/v0.1` and `wvp/v0.2` to run these tests. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the vectors and never adjusted here. Each
//! vector's whole expected report or refusal must be reproduced: the code of
//! a refusal; for an accepted package the decision, the value of every
//! requirement, the contract it is about, the number of statements and the
//! state of the issuer signature.
#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::{Path, PathBuf};

use verified_canonical::{Limits, Object, Sha256Digest, Value, parse};
use verified_protocol::ProtocolVersion;
use verified_verifier::{
    DecisionFinding, Evaluation, Expectations, IssuerSignature, Options, ProtocolSelection,
    Rejection, Report, Trust, verify,
};

fn corpus() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("VERIFIED_CONFORMANCE_DIR") else {
        assert!(
            std::env::var_os("VERIFIED_CONFORMANCE_REQUIRED").is_none(),
            "VERIFIED_CONFORMANCE_REQUIRED is set but VERIFIED_CONFORMANCE_DIR is not"
        );
        eprintln!("skipped: VERIFIED_CONFORMANCE_DIR is not set");
        return None;
    };
    Some(PathBuf::from(dir).join("wvp"))
}

fn read(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse(&bytes, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn member<'a>(object: &'a Object, name: &str, at: &str) -> &'a Value {
    object
        .get(name)
        .unwrap_or_else(|| panic!("{at}: no {name}"))
}

fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}

fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn trust(registry: &Value, at: &str) -> Option<Trust> {
    match registry {
        Value::Null => None,
        registry => Some(Trust::from_value(registry).unwrap_or_else(|e| panic!("{at}: {e}"))),
    }
}

/// A report in the form the corpus states its expectations in.
fn stated(report: &Report) -> Value {
    let (decision, requirements, statements) = match &report.decision {
        DecisionFinding::Reproduced(reproduced) => {
            let requirements = match &reproduced.evaluation {
                Evaluation::WorkContract { requirements, .. } => requirements
                    .iter()
                    .map(|r| object([("id", text(&r.id)), ("value", text(r.value.as_str()))]))
                    .collect(),
                _ => Vec::new(),
            };
            let count = i64::try_from(report.statements).expect("a small count");
            (
                text(reproduced.decision.as_str()),
                requirements,
                Value::Integer(count.into()),
            )
        }
        _ => (Value::Null, Vec::new(), Value::Null),
    };
    let issuer_signature = match report.issuer_signature {
        IssuerSignature::Established { .. } => "established",
        IssuerSignature::Absent => "absent",
        _ => "not checked",
    };
    let mut stated = Object::new();
    stated.insert("accept", Value::Bool(true));
    stated.insert("integrity", Value::Bool(report.integrity.is_established()));
    stated.insert("decision", decision);
    stated.insert("statements", statements);
    stated.insert("issuerSignature", text(issuer_signature));
    if let Some(contract) = &report.contract {
        let digest = object([
            ("algorithm", text(Sha256Digest::ALGORITHM)),
            ("hex", text(&contract.digest.to_hex())),
        ]);
        stated.insert(
            "contract",
            object([
                ("id", text(&contract.id)),
                ("version", text(&contract.version)),
                ("digest", digest),
            ]),
        );
        stated.insert("requirements", Value::Array(requirements));
    }
    Value::Object(stated)
}

fn refused(code: &str) -> Value {
    object([("accept", Value::Bool(false)), ("error", text(code))])
}

fn outcome(result: Result<Report, Rejection>, at: &str) -> Value {
    match result {
        Ok(report) => stated(&report),
        Err(Rejection::Refused(refusal)) => refused(refusal.code.as_str()),
        Err(other) => panic!("{at}: {other}"),
    }
}

fn run_vector(path: &Path, class: &str) {
    let at = path.display().to_string();
    let vector = read(path);
    let vector = vector.as_object().expect("a vector is an object");
    let protocol: ProtocolVersion = member(vector, "protocol", &at)
        .as_str()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("{at}: unknown protocol"));
    let package = member(vector, "packageJson", &at)
        .as_str()
        .expect("packageJson is text");
    let trust = trust(member(vector, "registry", &at), &at);
    let options = Options {
        protocol: ProtocolSelection::Require(protocol),
        trust: trust.as_ref(),
        ..Options::default()
    };
    let actual = outcome(verify(package.as_bytes(), &options), &at);
    let expected = member(vector, "expected", &at);
    assert_eq!(&actual, expected, "{at}");
    let accepted = matches!(
        expected.as_object().and_then(|e| e.get("accept")),
        Some(Value::Bool(true))
    );
    assert_eq!(
        accepted,
        class == "valid",
        "{at}: the vector's class and its expectation disagree"
    );
}

#[test]
fn every_package_vector_is_reproduced() {
    let Some(root) = corpus() else { return };
    let mut vectors = 0;
    for version in ["v0.1", "v0.2"] {
        for class in ["valid", "must-reject", "invalid"] {
            let dir = root.join(version).join(class);
            let mut paths: Vec<_> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
                .map(|entry| entry.expect("readable entry").path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            paths.sort();
            assert!(!paths.is_empty(), "{}: no vectors", dir.display());
            for path in paths {
                run_vector(&path, class);
                vectors += 1;
            }
        }
    }
    eprintln!("wvp corpus: {vectors} package vectors reproduced, decisions included");
}

#[test]
fn every_expectation_case_is_reproduced() {
    let Some(root) = corpus() else { return };
    let path = root.join("v0.2").join("expectations.json");
    let cases = read(&path);
    let cases = cases.as_array().expect("expectations.json is an array");
    assert_ne!(cases.len(), 0, "{}: no cases", path.display());
    for (i, case) in cases.iter().enumerate() {
        let at = format!("{}#{i}", path.display());
        let case = case.as_object().expect("a case is an object");
        let expect = member(case, "expect", &at)
            .as_object()
            .expect("expect is an object");
        let string = |name| expect.get(name).and_then(Value::as_str).map(str::to_owned);
        let contract = expect.get("contract").map(|digest| {
            let digest = digest.as_object().expect("a digest object");
            assert_eq!(
                member(digest, "algorithm", &at).as_str(),
                Some("sha-256"),
                "{at}"
            );
            let hex = member(digest, "hex", &at).as_str().expect("hex is text");
            hex.parse::<Sha256Digest>()
                .unwrap_or_else(|e| panic!("{at}: {e}"))
        });
        let trust = trust(member(case, "registry", &at), &at);
        let options = Options {
            protocol: ProtocolSelection::Require(ProtocolVersion::V0_2),
            trust: trust.as_ref(),
            expectations: Expectations {
                tenant: string("tenant"),
                contract,
                claim: string("claim"),
            },
            ..Options::default()
        };
        let package = member(case, "packageJson", &at)
            .as_str()
            .expect("packageJson is text");
        let actual = match verify(package.as_bytes(), &options) {
            Ok(report) => {
                let DecisionFinding::Reproduced(reproduced) = &report.decision else {
                    panic!("{at}: the decision was not reproduced");
                };
                object([
                    ("accept", Value::Bool(true)),
                    ("decision", text(reproduced.decision.as_str())),
                ])
            }
            Err(Rejection::Refused(refusal)) => refused(refusal.code.as_str()),
            Err(other) => panic!("{at}: {other}"),
        };
        assert_eq!(&actual, member(case, "expected", &at), "{at}");
    }
    eprintln!("wvp corpus: {} expectation cases reproduced", cases.len());
}

/// The worked examples published next to the specifications: one package
/// each and the registry a relying party would supply.
#[test]
fn the_worked_examples_verify_as_supported() {
    let Some(root) = corpus() else { return };
    // The examples sit beside the specifications, not the vectors.
    let Some(protocols) = root
        .parent()
        .and_then(Path::parent)
        .map(|r| r.join("protocols"))
    else {
        return;
    };
    if !protocols.is_dir() {
        eprintln!("skipped: no protocols directory beside the corpus");
        return;
    }
    for example in [
        "wvp/v0.1/examples/order-transition",
        "wvp/v0.2/examples/invoice-processing",
    ] {
        let dir = protocols.join(example);
        let at = dir.display().to_string();
        let trust = Trust::from_value(&read(&dir.join("registry.json")))
            .unwrap_or_else(|e| panic!("{at}: {e}"));
        let package =
            std::fs::read(dir.join("package.json")).unwrap_or_else(|e| panic!("{at}: {e}"));
        let options = Options {
            trust: Some(&trust),
            ..Options::default()
        };
        let report =
            verify(package.trim_ascii_end(), &options).unwrap_or_else(|e| panic!("{at}: {e}"));
        assert!(report.is_complete(), "{at}");
        let DecisionFinding::Reproduced(reproduced) = &report.decision else {
            panic!("{at}: the decision was not reproduced");
        };
        assert_eq!(reproduced.decision.as_str(), "SUPPORTED", "{at}");
    }
}
