//! The container checks, their order and their refusal codes, on synthetic
//! packages built in-process.

mod support;

use proptest::prelude::*;
use support::{Draft, PATHS, hash, json, object, string};
use verified_canonical::{LimitExceeded, Limits, Value};
use verified_protocol::{ComponentPath, ProtocolVersion, RefusalCode};
use verified_verifier::{Finding, NotChecked, Options, ProtocolSelection, Rejection, verify};

fn check(text: &str) -> Result<verified_verifier::Report, Rejection> {
    verify(text.as_bytes(), &Options::default())
}

fn refusal(draft: &Draft) -> RefusalCode {
    match check(&draft.text()) {
        Err(Rejection::Refused(refusal)) => refusal.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn draft() -> Draft {
    Draft::consistent("wvp-0.2")
}

#[test]
fn a_consistent_container_is_reported_and_nothing_more_is_claimed() {
    let draft = draft();
    let report = check(&draft.text()).expect("not refused");

    assert_eq!(report.protocol, ProtocolVersion::V0_2);
    assert_eq!(
        report.package_id.to_string(),
        format!("wvp:sha-256:{}", draft.manifest().digest())
    );
    assert_eq!(report.components.map(|c| c.path), ComponentPath::ALL);
    for (component, (_, content)) in report.components.iter().zip(&draft.files) {
        assert_eq!(component.digest, content.digest());
    }
    assert_eq!(report.issuer_signatures_carried, 0);

    let pending = Finding::NotChecked(NotChecked::NotImplemented);
    assert_eq!(report.container, Finding::Established);
    assert_eq!(report.component_shapes, pending);
    assert_eq!(report.evidence_signatures, pending);
    assert_eq!(report.signer_authority, pending);
    assert_eq!(report.decision_reproduced, pending);
    assert_eq!(report.issuer_signature, pending);
    // Integrity needs step 7, which did not run.
    assert_eq!(report.integrity(), pending);
    assert!(!report.is_complete());
}

#[test]
fn both_protocol_versions_are_detected_and_never_interchanged() {
    for version in ProtocolVersion::ALL {
        let text = Draft::consistent(version.identifier()).text();
        assert_eq!(check(&text).expect("not refused").protocol, version);

        for required in ProtocolVersion::ALL {
            let options = Options {
                protocol: ProtocolSelection::Require(required),
                ..Options::default()
            };
            let result = verify(text.as_bytes(), &options);
            if required == version {
                assert_eq!(result.expect("not refused").protocol, version);
            } else {
                assert!(
                    matches!(&result, Err(Rejection::Refused(r)) if r.code == RefusalCode::UnsupportedVersion),
                    "{version} as {required}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn step_1_text_that_is_not_canonical() {
    let canonical = draft().text();
    let spaced = canonical.replacen(':', ": ", 1);
    let bom = format!("\u{feff}{canonical}");
    let newline = format!("{canonical}\n");
    let cases: [&[u8]; 8] = [
        b"",
        b"{",
        b"not json",
        b"{\"a\":1,\"a\":1}",
        b"\xff",
        spaced.as_bytes(),
        bom.as_bytes(),
        newline.as_bytes(),
    ];
    for input in cases {
        match verify(input, &Options::default()) {
            Err(Rejection::Refused(r)) => assert_eq!(r.code, RefusalCode::NotCanonical),
            other => panic!("{:?}: {other:?}", String::from_utf8_lossy(input)),
        }
    }
}

#[test]
fn step_2_unsupported_versions() {
    let wrong: [fn(&mut Draft); 8] = [
        |d| d.protocol = string("wvp-0.3"),
        |d| d.protocol = string("WVP-0.2"),
        |d| d.protocol = Value::Integer(2.into()),
        |d| d.package_version = Value::Integer(1.into()),
        |d| d.package_version = Value::Integer(3.into()),
        |d| d.package_version = string("2"),
        |d| d.canonical_version = string("verified-json-v2"),
        |d| d.canonical_version = Value::Null,
    ];
    for change in wrong {
        let mut d = draft();
        change(&mut d);
        assert_eq!(refusal(&d), RefusalCode::UnsupportedVersion);
    }
    // Text that is canonical JSON but no package at all has no version.
    for text in ["null", "[]", "{}", "7", r#"{"manifest":[]}"#] {
        assert!(
            matches!(check(text), Err(Rejection::Refused(r)) if r.code == RefusalCode::UnsupportedVersion),
            "{text}"
        );
    }
}

#[test]
fn step_3_a_container_of_the_wrong_shape() {
    let valid = draft().value();
    let Value::Object(members) = &valid else {
        unreachable!()
    };

    let mut extra = members.clone();
    extra.insert("note", Value::Null);
    let mut mistyped = members.clone();
    mistyped.insert("signatures", object([]));
    let mut signature = members.clone();
    signature.insert(
        "signatures",
        json(r#"[{"encoded":"AA==","keyId":"k","scheme":"Ed25519","x":1}]"#),
    );
    let mut missing: verified_canonical::Object = members
        .iter()
        .filter(|(k, _)| *k != "packageId")
        .map(|(k, v)| (k.to_owned(), v.clone()))
        .collect();
    missing.insert("files", members.get("files").expect("present").clone());

    for package in [extra, mistyped, signature, missing] {
        let text = Value::Object(package).to_canonical_string();
        assert!(
            matches!(check(&text), Err(Rejection::Refused(r)) if r.code == RefusalCode::MalformedComponent),
            "{text}"
        );
    }

    let mut d = draft();
    d.files[0].0 = Value::Integer(1.into());
    assert_eq!(refusal(&d), RefusalCode::MalformedComponent);
    let mut d = draft();
    d.package_commitment = Some(string("sha-256:00"));
    assert_eq!(refusal(&d), RefusalCode::MalformedComponent);
}

#[test]
fn step_4_a_component_set_that_is_not_the_protocols() {
    let wrong: [fn(&mut Draft); 6] = [
        |d| {
            d.files.pop();
        },
        |d| d.files.push((string("extra.json"), Value::Null)),
        |d| d.files.swap(0, 1),
        |d| d.files[5].0 = string("Inputs.json"),
        |d| d.files[3].0 = string("evidence/../claim.json"),
        |d| {
            let mut listed: Vec<_> = d
                .files
                .iter()
                .map(|(path, content)| (path.clone(), hash(content)))
                .collect();
            listed.swap(4, 5);
            d.manifest_files = Some(listed);
        },
    ];
    for change in wrong {
        let mut d = draft();
        change(&mut d);
        assert_eq!(refusal(&d), RefusalCode::ComponentSet);
    }
}

#[test]
fn step_5_a_component_that_is_not_what_the_manifest_commits_to() {
    for (index, path) in PATHS.into_iter().enumerate() {
        // Change the content after the manifest was fixed.
        let mut d = draft();
        d.manifest_files = Some(
            d.files
                .iter()
                .map(|(path, content)| (path.clone(), hash(content)))
                .collect(),
        );
        d.files[index].1 = object([("synthetic", string("altered"))]);
        assert_eq!(refusal(&d), RefusalCode::ComponentDigest, "{path}");
    }
    // The right hexadecimal text under another algorithm name, or in upper
    // case, does not state the digest.
    for respell in [
        (|content| {
            object([
                ("algorithm", string("md5")),
                ("hex", string(content.digest().to_hex())),
            ])
        }) as fn(&Value) -> Value,
        |content| {
            object([
                ("algorithm", string("sha-256")),
                ("hex", string(content.digest().to_hex().to_uppercase())),
            ])
        },
    ] {
        let mut d = draft();
        d.manifest_files = Some(
            d.files
                .iter()
                .enumerate()
                .map(|(i, (path, content))| {
                    (
                        path.clone(),
                        if i == 2 {
                            respell(content)
                        } else {
                            hash(content)
                        },
                    )
                })
                .collect(),
        );
        assert_eq!(refusal(&d), RefusalCode::ComponentDigest);
    }
}

#[test]
fn step_6_a_commitment_or_identifier_that_does_not_follow_from_the_manifest() {
    type Change<'a> = Box<dyn Fn(&mut Draft) + 'a>;
    let other = hash(&Value::Null);
    let manifest = draft().manifest();
    let right_hex = manifest.digest().to_hex();
    let wrong: [Change; 5] = [
        Box::new(|d| d.package_commitment = Some(other.clone())),
        Box::new(|d| {
            d.package_commitment = Some(object([
                ("algorithm", string("sha-512")),
                ("hex", string(right_hex.clone())),
            ]));
        }),
        Box::new(|d| d.package_id = Some(string(format!("wvp:sha-256:{}", Value::Null.digest())))),
        Box::new(|d| d.package_id = Some(string(right_hex.clone()))),
        Box::new(|d| d.package_id = Some(string(format!("WVP:sha-256:{right_hex}")))),
    ];
    for change in wrong {
        let mut d = draft();
        change(&mut d);
        assert_eq!(refusal(&d), RefusalCode::CommitmentMismatch);
    }
}

#[test]
fn the_first_failing_step_is_the_one_reported() {
    // Every later defect at once: the version wins.
    let mut d = draft();
    d.protocol = string("wvp-9");
    d.signatures = object([]);
    d.files.swap(0, 1);
    d.package_commitment = Some(hash(&Value::Null));
    assert_eq!(refusal(&d), RefusalCode::UnsupportedVersion);

    // Shape before component set before digests before commitment.
    d.protocol = string("wvp-0.2");
    assert_eq!(refusal(&d), RefusalCode::MalformedComponent);
    d.signatures = Value::Array(Vec::new());
    assert_eq!(refusal(&d), RefusalCode::ComponentSet);
    d.files.swap(0, 1);
    d.manifest_files = Some(
        d.files
            .iter()
            .map(|(path, _)| (path.clone(), hash(&Value::Null)))
            .collect(),
    );
    assert_eq!(refusal(&d), RefusalCode::ComponentDigest);
    d.manifest_files = None;
    assert_eq!(refusal(&d), RefusalCode::CommitmentMismatch);
    d.package_commitment = None;
    assert!(check(&d.text()).is_ok());
}

#[test]
fn carried_issuer_signatures_are_counted_not_verified() {
    let mut d = draft();
    d.signatures = json(r#"[{"encoded":"AA==","keyId":"anyone","scheme":"Ed25519"}]"#);
    let report = check(&d.text()).expect("not refused");
    assert_eq!(report.issuer_signatures_carried, 1);
    assert_eq!(
        report.issuer_signature,
        Finding::NotChecked(NotChecked::NotImplemented)
    );
}

#[test]
fn a_resource_limit_is_not_a_protocol_refusal() {
    let text = draft().text();
    let options = Options {
        limits: Limits {
            max_bytes: text.len() - 1,
            ..Limits::DEFAULT
        },
        ..Options::default()
    };
    assert_eq!(
        verify(text.as_bytes(), &options),
        Err(Rejection::Limit(LimitExceeded::Bytes {
            limit: text.len() - 1
        }))
    );
    let options = Options {
        limits: Limits {
            max_depth: 2,
            ..Limits::DEFAULT
        },
        ..Options::default()
    };
    assert_eq!(
        verify(text.as_bytes(), &options),
        Err(Rejection::Limit(LimitExceeded::Depth { limit: 2 }))
    );
}

proptest! {
    /// The draft carries no signatures, so every byte of it is covered by a
    /// container check: no altered text is reported on.
    #[test]
    fn any_single_byte_change_is_refused(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let text = draft().text();
        let mut bytes = text.clone().into_bytes();
        let i = index.index(bytes.len());
        prop_assume!(bytes[i] != byte);
        bytes[i] = byte;
        prop_assert!(matches!(verify(&bytes, &Options::default()), Err(Rejection::Refused(_))));
    }

    #[test]
    fn verification_is_deterministic_and_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let options = Options::default();
        prop_assert_eq!(verify(&bytes, &options), verify(&bytes, &options));
    }

    #[test]
    fn any_component_content_is_committed_to(seed in "[a-z]{0,12}", index in 0usize..6) {
        let mut a = draft();
        a.files[index].1 = string(seed.clone());
        let report = check(&a.text()).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(report.components[index].digest, string(seed).digest());
        // And the identifier moves with the content.
        prop_assert_ne!(report.package_id, check(&draft().text()).map_err(|e| TestCaseError::fail(e.to_string()))?.package_id);
    }
}
