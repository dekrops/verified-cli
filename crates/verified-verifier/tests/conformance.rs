//! The WVP conformance corpus, as far as this version of the verifier goes.
//!
//! The corpus is not part of this repository until its publication is
//! approved; see `conformance/README.md`. Point `VERIFIED_CONFORMANCE_DIR`
//! at a directory holding `wvp/v0.1` and `wvp/v0.2` to run this test. With
//! `VERIFIED_CONFORMANCE_REQUIRED=1` its absence is a failure.
//!
//! Expected outcomes are read from the vectors and never adjusted here. For
//! each vector:
//!
//! - a refusal the container checks own must be reproduced exactly;
//! - an accepted package must pass the container checks;
//! - a refusal a later step owns must not be pre-empted by a different code:
//!   the package must pass the container checks, and is counted as
//!   *deferred*, not as conforming.
#![allow(clippy::print_stderr)] // progress notes for whoever runs the corpus

use std::path::{Path, PathBuf};

use verified_canonical::{Limits, Object, Value, parse};
use verified_protocol::{ProtocolVersion, RefusalCode};
use verified_verifier::{Options, ProtocolSelection, Rejection, verify};

/// The codes steps 1, 2 and 4 to 6 own. `MALFORMED_COMPONENT` is shared with
/// step 7, which this version lacks, so it is handled separately.
const OWNED: [RefusalCode; 5] = [
    RefusalCode::NotCanonical,
    RefusalCode::UnsupportedVersion,
    RefusalCode::ComponentSet,
    RefusalCode::ComponentDigest,
    RefusalCode::CommitmentMismatch,
];

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

fn member<'a>(object: &'a Object, name: &str, path: &Path) -> &'a Value {
    object
        .get(name)
        .unwrap_or_else(|| panic!("{}: no {name}", path.display()))
}

#[derive(Default)]
struct Tally {
    reproduced_refusals: usize,
    accepted_containers: usize,
    deferred_refusals: usize,
}

fn run_vector(path: &Path, tally: &mut Tally) {
    let vector = read(path);
    let vector = vector.as_object().expect("a vector is an object");
    let protocol: ProtocolVersion = member(vector, "protocol", path)
        .as_str()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("{}: unknown protocol", path.display()));
    let text = member(vector, "packageJson", path)
        .as_str()
        .expect("packageJson is text");
    let expected = member(vector, "expected", path)
        .as_object()
        .expect("expected is an object");
    let accept = match member(expected, "accept", path) {
        Value::Bool(accept) => *accept,
        other => panic!("{}: accept is {other:?}", path.display()),
    };
    let expected_error = expected.get("error").and_then(Value::as_str);

    let options = Options {
        protocol: ProtocolSelection::Require(protocol),
        ..Options::default()
    };
    let outcome = verify(text.as_bytes(), &options);
    let at = path.display();

    match (accept, expected_error, &outcome) {
        (true, None, Ok(report)) => {
            assert_eq!(report.protocol, protocol, "{at}");
            tally.accepted_containers += 1;
        }
        (false, Some(code), Err(Rejection::Refused(refusal))) if refusal.code.as_str() == code => {
            tally.reproduced_refusals += 1;
        }
        (false, Some(code), Ok(_)) if !OWNED.iter().any(|owned| owned.as_str() == code) => {
            tally.deferred_refusals += 1;
        }
        _ => panic!("{at}: expected accept={accept} error={expected_error:?}, got {outcome:?}"),
    }
}

#[test]
fn wvp_corpus_container_checks() {
    let Some(root) = corpus() else { return };
    let mut tally = Tally::default();
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
                run_vector(&path, &mut tally);
                vectors += 1;
            }
        }
    }
    eprintln!(
        "wvp corpus: {vectors} vectors; {} refusals reproduced, {} accepted packages pass the \
         container checks, {} refusals deferred to checks not implemented yet",
        tally.reproduced_refusals, tally.accepted_containers, tally.deferred_refusals
    );
    assert!(tally.reproduced_refusals > 0 && tally.accepted_containers > 0);
}
