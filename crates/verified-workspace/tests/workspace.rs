// SPDX-License-Identifier: Apache-2.0

//! A workspace on a real file system, with synthetic packages.

#[path = "../../verified-verifier/tests/support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};

use support::{Scenario, hash, issuer_key, replaced, string};
use verified_canonical::{Limits, Value};
use verified_protocol::{ProtocolVersion, RefusalCode};
use verified_verifier::Rejection;
use verified_workspace::{DIRECTORY, Error, ImportError, ObjectId, ResolveError, Workspace};

const LIMITS: Limits = Limits::DEFAULT;

/// A directory under the system's temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verified-workspace-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch directory");
        Self(dir)
    }

    fn workspace(&self) -> Workspace {
        Workspace::init(&self.0).expect("init").0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every regular file under `dir`, relative to it.
fn files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                out.push(path.strip_prefix(root).expect("under root").to_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn init_creates_a_workspace_once_and_it_is_found_from_below() {
    let scratch = Scratch::new("init");
    let (workspace, created) = Workspace::init(&scratch.0).expect("init");
    assert!(created);
    assert_eq!(workspace.directory(), scratch.0.join(DIRECTORY));
    assert_eq!(files(workspace.directory()), [PathBuf::from("format")]);

    let (again, created) = Workspace::init(&scratch.0).expect("init again");
    assert!(!created);
    assert_eq!(again, workspace);

    let nested = scratch.0.join("a").join("b");
    std::fs::create_dir_all(&nested).expect("nested directories");
    assert_eq!(Workspace::discover(&nested).expect("found"), workspace);
}

#[test]
fn outside_a_workspace_nothing_is_found_or_created() {
    let scratch = Scratch::new("outside");
    assert!(matches!(
        Workspace::discover(&scratch.0),
        Err(Error::NotFound { .. })
    ));
    assert_eq!(files(&scratch.0), Vec::<PathBuf>::new());
}

#[test]
fn a_workspace_of_another_format_is_not_touched() {
    let scratch = Scratch::new("format");
    let workspace = scratch.workspace();
    std::fs::write(
        workspace.directory().join("format"),
        "verified-workspace-2\n",
    )
    .expect("write");
    for result in [
        Workspace::discover(&scratch.0),
        Workspace::init(&scratch.0).map(|w| w.0),
    ] {
        assert!(
            matches!(&result, Err(Error::UnsupportedFormat { found, .. }) if found == "verified-workspace-2"),
            "{result:?}"
        );
    }
    // A directory that merely has the name is not a workspace either.
    std::fs::remove_file(workspace.directory().join("format")).expect("remove");
    assert!(matches!(
        Workspace::discover(&scratch.0),
        Err(Error::UnsupportedFormat { .. })
    ));
}

#[test]
fn import_stores_the_exact_bytes_under_the_packages_own_identifier() {
    let scratch = Scratch::new("import");
    let workspace = scratch.workspace();
    let draft = Scenario::posted().draft();
    let text = draft.text();

    let imported = workspace
        .import(text.as_bytes(), 1_772_359_200, &LIMITS)
        .expect("imported");
    assert!(!imported.already_present);
    assert_eq!(imported.protocol, ProtocolVersion::V0_2);
    assert_eq!(
        imported.stored.package.to_string(),
        format!("wvp:sha-256:{}", draft.manifest().digest())
    );
    assert_eq!(imported.stored.object, ObjectId::of(text.as_bytes()));
    assert_eq!(workspace.stored().expect("listed"), [imported.stored]);
    assert_eq!(
        workspace.read(&imported.stored, &LIMITS).expect("read"),
        text.as_bytes()
    );

    // The only names on disk are digests this tool derived.
    let commitment = draft.manifest().digest().to_hex();
    let object = PathBuf::from("packages")
        .join(&commitment[..2])
        .join(&commitment[2..])
        .join(imported.stored.object.digest().to_hex());
    assert_eq!(
        files(workspace.directory()),
        [
            PathBuf::from("format"),
            PathBuf::from("imports.log"),
            object
        ]
    );
}

#[test]
fn importing_again_changes_no_object_and_is_recorded_as_another_import() {
    let scratch = Scratch::new("again");
    let workspace = scratch.workspace();
    let text = Scenario::posted().text();
    let first = workspace
        .import(text.as_bytes(), 100, &LIMITS)
        .expect("imported");
    let second = workspace
        .import(text.as_bytes(), 200, &LIMITS)
        .expect("imported again");
    assert!(second.already_present);
    assert_eq!(second.stored, first.stored);
    assert_eq!(workspace.stored().expect("listed").len(), 1);

    let history = workspace.history().expect("history");
    assert_eq!(history.damaged, 0);
    let times: Vec<u64> = history.records.iter().map(|r| r.imported_at_unix).collect();
    assert_eq!(times, [100, 200]);
    assert!(history.records.iter().all(|r| r.stored == first.stored));
}

#[test]
fn importing_is_not_accepting_and_consults_no_trust() {
    // Nobody's registry holds this package's signing key, and its recorded
    // decision does not follow from its evidence. It has integrity, so it is
    // stored, and storing it says nothing more.
    let scratch = Scratch::new("untrusted");
    let workspace = scratch.workspace();
    let mut scenario = Scenario::posted();
    scenario.outcome = replaced(
        &scenario.outcome,
        &["decision"],
        Some(string("CONTRADICTED")),
    );
    assert!(
        workspace
            .import(scenario.text().as_bytes(), 0, &LIMITS)
            .is_ok()
    );
}

#[test]
fn a_package_without_integrity_is_not_stored() {
    let scratch = Scratch::new("refused");
    let workspace = scratch.workspace();
    let mut tampered = Scenario::posted().draft();
    tampered.manifest_files = Some(
        tampered
            .files
            .iter()
            .map(|(path, content)| (path.clone(), hash(content)))
            .collect(),
    );
    tampered.files[0].1 = Value::Null;
    let mut malformed = Scenario::posted();
    malformed.claim = replaced(&malformed.claim, &["extra"], Some(Value::Null));

    let cases = [
        (tampered.text(), RefusalCode::ComponentDigest),
        (malformed.text(), RefusalCode::MalformedComponent),
        (
            format!("{}\n", Scenario::posted().text()),
            RefusalCode::NotCanonical,
        ),
        (String::new(), RefusalCode::NotCanonical),
    ];
    for (text, code) in cases {
        let result = workspace.import(text.as_bytes(), 0, &LIMITS);
        assert!(
            matches!(&result, Err(ImportError::Rejected(Rejection::Refused(r))) if r.code == code),
            "{code}: {result:?}"
        );
    }
    assert_eq!(workspace.stored().expect("listed"), []);
    assert_eq!(workspace.history().expect("history").records, []);
    assert_eq!(files(workspace.directory()), [PathBuf::from("format")]);
}

#[test]
fn one_package_identifier_can_name_texts_that_differ_in_issuer_signatures() {
    let scratch = Scratch::new("variants");
    let workspace = scratch.workspace();
    let unsigned = Scenario::posted();
    let mut signed = unsigned.clone();
    signed.issuers = vec![issuer_key()];

    let a = workspace
        .import(unsigned.text().as_bytes(), 0, &LIMITS)
        .expect("imported");
    let b = workspace
        .import(signed.text().as_bytes(), 0, &LIMITS)
        .expect("imported");
    assert_eq!(a.stored.package, b.stored.package);
    assert_ne!(a.stored.object, b.stored.object);
    assert!(!b.already_present);

    // Neither text is silently preferred.
    let by_package = workspace.resolve(&a.stored.package.to_string());
    assert!(
        matches!(&by_package, Err(ResolveError::Variants { objects, .. }) if objects.len() == 2),
        "{by_package:?}"
    );
    for stored in [a.stored, b.stored] {
        assert_eq!(
            workspace
                .resolve(&stored.object.to_string())
                .expect("resolved"),
            stored
        );
    }
    assert_eq!(
        workspace.read(&b.stored, &LIMITS).expect("read"),
        signed.text().as_bytes()
    );
}

#[test]
fn names_resolve_by_identifier_or_prefix_and_nothing_else() {
    let scratch = Scratch::new("resolve");
    let workspace = scratch.workspace();
    let posted = workspace
        .import(Scenario::posted().text().as_bytes(), 0, &LIMITS)
        .expect("imported")
        .stored;
    let shipped = workspace
        .import(Scenario::shipped().text().as_bytes(), 0, &LIMITS)
        .expect("imported")
        .stored;

    for stored in [posted, shipped] {
        let package = stored.package.commitment().to_hex();
        let object = stored.object.digest().to_hex();
        for name in [
            stored.package.to_string(),
            package.clone(),
            package[..8].to_owned(),
            format!("wvp:sha-256:{}", &package[..8]),
            stored.object.to_string(),
            format!("object:sha-256:{}", &object[..8]),
        ] {
            assert_eq!(
                workspace.resolve(&name).expect("resolved"),
                stored,
                "{name}"
            );
        }
    }
    let unknown = "0".repeat(64);
    assert!(matches!(
        workspace.resolve(&unknown),
        Err(ResolveError::NotFound(_))
    ));
    for invalid in [
        "",
        "abc",
        "ABCDEF",
        "../../etc/passwd",
        "wvp:sha-256:",
        "object:sha-256:xyz1",
        "wvp:sha-512:abcd",
    ] {
        assert!(
            matches!(workspace.resolve(invalid), Err(ResolveError::Invalid(_))),
            "{invalid}"
        );
    }
}

#[test]
fn a_damaged_object_is_never_returned() {
    let scratch = Scratch::new("damage");
    let workspace = scratch.workspace();
    let posted = workspace
        .import(Scenario::posted().text().as_bytes(), 0, &LIMITS)
        .expect("imported")
        .stored;
    let shipped_text = Scenario::shipped().text();
    let shipped = workspace
        .import(shipped_text.as_bytes(), 0, &LIMITS)
        .expect("imported")
        .stored;
    let path = |stored: &verified_workspace::Stored| {
        let hex = stored.package.commitment().to_hex();
        workspace
            .directory()
            .join("packages")
            .join(&hex[..2])
            .join(&hex[2..])
            .join(stored.object.digest().to_hex())
    };

    // Altered in place.
    let mut bytes = std::fs::read(path(&posted)).expect("read");
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    std::fs::write(path(&posted), &bytes).expect("write");
    assert!(matches!(
        workspace.read(&posted, &LIMITS),
        Err(Error::Corrupt { .. })
    ));
    // Importing the original again does not paper over the damage.
    let again = workspace.import(Scenario::posted().text().as_bytes(), 0, &LIMITS);
    assert!(
        matches!(again, Err(ImportError::Workspace(Error::Corrupt { .. }))),
        "{again:?}"
    );

    // Another package's intact text, under this package's object name.
    std::fs::write(path(&posted), &shipped_text).expect("write");
    assert!(matches!(
        workspace.read(&posted, &LIMITS),
        Err(Error::Corrupt { .. })
    ));

    // An intact text filed under another package's directory.
    let hex = posted.package.commitment().to_hex();
    let misplaced = workspace
        .directory()
        .join("packages")
        .join(&hex[..2])
        .join(&hex[2..])
        .join(shipped.object.digest().to_hex());
    std::fs::copy(path(&shipped), &misplaced).expect("copy");
    let misfiled = verified_workspace::Stored {
        package: posted.package,
        object: shipped.object,
    };
    assert!(matches!(
        workspace.read(&misfiled, &LIMITS),
        Err(Error::Corrupt { .. })
    ));
    // The intact original still reads.
    assert_eq!(
        workspace.read(&shipped, &LIMITS).expect("read"),
        shipped_text.as_bytes()
    );
}

#[cfg(unix)]
#[test]
fn symbolic_links_inside_a_workspace_are_not_followed() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new("symlink");
    let workspace = scratch.workspace();
    let text = Scenario::posted().text();
    let stored = workspace
        .import(text.as_bytes(), 0, &LIMITS)
        .expect("imported")
        .stored;
    let hex = stored.package.commitment().to_hex();
    let object = workspace
        .directory()
        .join("packages")
        .join(&hex[..2])
        .join(&hex[2..])
        .join(stored.object.digest().to_hex());

    // An object replaced by a link to a file with the right content.
    let outside = scratch.0.join("outside.json");
    std::fs::write(&outside, &text).expect("write");
    std::fs::remove_file(&object).expect("remove");
    symlink(&outside, &object).expect("link");
    assert!(matches!(
        workspace.read(&stored, &LIMITS),
        Err(Error::Unsafe { .. })
    ));
    assert!(matches!(
        workspace.import(text.as_bytes(), 0, &LIMITS),
        Err(ImportError::Workspace(Error::Unsafe { .. }))
    ));

    // The store itself replaced by a link.
    let elsewhere = scratch.0.join("elsewhere");
    std::fs::rename(workspace.directory().join("packages"), &elsewhere).expect("move");
    symlink(&elsewhere, workspace.directory().join("packages")).expect("link");
    assert!(matches!(workspace.stored(), Err(Error::Unsafe { .. })));
    assert!(matches!(
        workspace.import(Scenario::shipped().text().as_bytes(), 0, &LIMITS),
        Err(ImportError::Workspace(Error::Unsafe { .. }))
    ));

    // The workspace directory itself as a link.
    let other = Scratch::new("symlink-target");
    let real = other.workspace();
    let linked = scratch.0.join("linked");
    std::fs::create_dir(&linked).expect("create");
    symlink(real.directory(), linked.join(DIRECTORY)).expect("link");
    assert!(matches!(
        Workspace::discover(&linked),
        Err(Error::Unsafe { .. })
    ));
}

#[test]
fn files_this_tool_did_not_write_are_reported_not_skipped() {
    let scratch = Scratch::new("foreign");
    let workspace = scratch.workspace();
    workspace
        .import(Scenario::posted().text().as_bytes(), 0, &LIMITS)
        .expect("imported");
    // A leftover temporary file from an interrupted import is not an object.
    std::fs::write(
        workspace.directory().join("packages").join(".tmp-1-0"),
        "partial",
    )
    .expect("write");
    assert_eq!(workspace.stored().expect("listed").len(), 1);

    std::fs::write(
        workspace.directory().join("packages").join("README"),
        "hello",
    )
    .expect("write");
    assert!(matches!(workspace.stored(), Err(Error::Unsafe { .. })));
}

#[test]
fn damaged_history_lines_are_counted_and_never_guessed_at() {
    let scratch = Scratch::new("history");
    let workspace = scratch.workspace();
    assert_eq!(workspace.history().expect("history").records, []);
    let text = Scenario::posted().text();
    workspace
        .import(text.as_bytes(), 10, &LIMITS)
        .expect("imported");

    let log = workspace.directory().join("imports.log");
    let mut bytes = std::fs::read(&log).expect("read");
    let good = bytes.clone();
    bytes.extend_from_slice(b"{\"record\":\"verified-import-9\"}\n");
    bytes.extend_from_slice(b"not json\n");
    // A record cut short by an interrupted write.
    bytes.extend_from_slice(&good[..good.len() / 2]);
    std::fs::write(&log, &bytes).expect("write");

    let history = workspace.history().expect("history");
    assert_eq!(history.records.len(), 1);
    assert_eq!(history.records[0].imported_at_unix, 10);
    assert_eq!(history.damaged, 3);
}

// ---- checking a whole workspace --------------------------------------------

use verified_workspace::{Problem, Stored};

fn object_path(workspace: &Workspace, stored: &Stored) -> PathBuf {
    let hex = stored.package.commitment().to_hex();
    workspace
        .directory()
        .join("packages")
        .join(&hex[..2])
        .join(&hex[2..])
        .join(stored.object.digest().to_hex())
}

#[test]
fn a_sound_workspace_checks_clean_and_is_not_changed_by_checking() {
    let scratch = Scratch::new("check-clean");
    let workspace = scratch.workspace();
    assert_eq!(workspace.check(&LIMITS).expect("checked").problems, []);

    workspace
        .import(Scenario::posted().text().as_bytes(), 1, &LIMITS)
        .expect("imported");
    workspace
        .import(Scenario::shipped().text().as_bytes(), 2, &LIMITS)
        .expect("imported");
    workspace
        .import(Scenario::shipped().text().as_bytes(), 3, &LIMITS)
        .expect("imported");
    let before = files(workspace.directory());
    let check = workspace.check(&LIMITS).expect("checked");
    assert_eq!((check.objects, check.records), (2, 3));
    assert_eq!(check.problems, []);
    assert!(!check.has_damage());
    assert_eq!(files(workspace.directory()), before);
}

#[test]
fn every_kind_of_damage_is_found_in_one_pass_and_nothing_is_repaired() {
    let scratch = Scratch::new("check-damage");
    let workspace = scratch.workspace();
    let posted = workspace
        .import(Scenario::posted().text().as_bytes(), 1, &LIMITS)
        .expect("imported")
        .stored;
    let shipped = workspace
        .import(Scenario::shipped().text().as_bytes(), 2, &LIMITS)
        .expect("imported")
        .stored;

    // One object altered, one deleted, a foreign file in two places, and a
    // history line that is not a record.
    let text = std::fs::read_to_string(object_path(&workspace, &posted)).expect("read");
    std::fs::write(
        object_path(&workspace, &posted),
        text.replace("INV-1", "INV-2"),
    )
    .expect("write");
    std::fs::remove_file(object_path(&workspace, &shipped)).expect("remove");
    std::fs::write(workspace.directory().join("notes.txt"), "mine").expect("write");
    std::fs::write(
        workspace.directory().join("packages").join("zz"),
        "not a directory",
    )
    .expect("write");
    let log = workspace.directory().join("imports.log");
    let mut history = std::fs::read(&log).expect("read");
    history.extend_from_slice(b"garbage\n");
    std::fs::write(&log, history).expect("write");

    let before = files(workspace.directory());
    let check = workspace.check(&LIMITS).expect("checked");
    assert!(check.has_damage());
    assert_eq!(check.objects, 1);
    let found = |wanted: fn(&Problem) -> bool| check.problems.iter().filter(|p| wanted(p)).count();
    assert_eq!(found(|p| matches!(p, Problem::Damaged { .. })), 1);
    assert_eq!(found(|p| matches!(p, Problem::MissingObject { .. })), 1);
    assert_eq!(
        found(|p| matches!(p, Problem::DamagedHistory { lines: 1 })),
        1
    );
    let foreign: Vec<&Path> = check
        .problems
        .iter()
        .filter_map(|p| match p {
            Problem::Foreign { path } => Some(path.as_path()),
            _ => None,
        })
        .collect();
    assert_eq!(
        foreign,
        [Path::new("notes.txt"), &Path::new("packages").join("zz")]
    );
    assert!(check.problems.iter().all(Problem::is_damage));
    assert!(matches!(
        &check.problems.iter().find(|p| matches!(p, Problem::Damaged { .. })),
        Some(Problem::Damaged { stored, .. }) if *stored == posted
    ));
    assert_eq!(files(workspace.directory()), before);
}

#[test]
fn traces_of_an_interrupted_import_are_reported_as_harmless() {
    let scratch = Scratch::new("check-interrupted");
    let workspace = scratch.workspace();
    let stored = workspace
        .import(Scenario::posted().text().as_bytes(), 1, &LIMITS)
        .expect("imported")
        .stored;
    // Interrupted before the object was renamed into place, and (another
    // time) after it was stored but before the import was recorded.
    let leftover = object_path(&workspace, &stored).with_file_name(".tmp-99-0");
    std::fs::write(&leftover, "partial").expect("write");
    std::fs::write(workspace.directory().join("imports.log"), "").expect("truncate");

    let check = workspace.check(&LIMITS).expect("checked");
    assert!(!check.has_damage(), "{:?}", check.problems);
    assert_eq!(check.problems.len(), 2);
    assert!(
        check
            .problems
            .iter()
            .any(|p| matches!(p, Problem::Leftover { .. }))
    );
    assert!(
        check
            .problems
            .iter()
            .any(|p| matches!(p, Problem::Unrecorded { stored: s } if *s == stored))
    );
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_in_the_store_is_found_and_not_followed() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new("check-symlink");
    let workspace = scratch.workspace();
    let text = Scenario::posted().text();
    let stored = workspace
        .import(text.as_bytes(), 1, &LIMITS)
        .expect("imported")
        .stored;
    let outside = scratch.0.join("outside.json");
    std::fs::write(&outside, &text).expect("write");
    std::fs::remove_file(object_path(&workspace, &stored)).expect("remove");
    symlink(&outside, object_path(&workspace, &stored)).expect("link");

    let check = workspace.check(&LIMITS).expect("checked");
    assert!(check.has_damage());
    // The link is foreign, so the object it stands in for is missing.
    assert_eq!(check.objects, 0);
    assert!(
        check
            .problems
            .iter()
            .any(|p| matches!(p, Problem::Foreign { .. }))
    );
    assert!(
        check
            .problems
            .iter()
            .any(|p| matches!(p, Problem::MissingObject { .. }))
    );
}

#[test]
fn a_history_too_large_to_read_is_damage_and_proves_nothing_about_the_objects() {
    let scratch = Scratch::new("check-oversized");
    let workspace = scratch.workspace();
    workspace
        .import(Scenario::posted().text().as_bytes(), 1, &LIMITS)
        .expect("imported");
    // Grown past what is read, without writing the bytes.
    let log = std::fs::OpenOptions::new()
        .write(true)
        .open(workspace.directory().join("imports.log"))
        .expect("open");
    log.set_len(64 * 1024 * 1024 + 1).expect("extend");

    assert!(matches!(
        workspace.history(),
        Err(Error::HistoryTooLarge { .. })
    ));
    let check = workspace.check(&LIMITS).expect("checked");
    assert!(check.has_damage());
    assert_eq!(check.objects, 1);
    assert!(
        matches!(
            check.problems.as_slice(),
            [Problem::UnreadableHistory { .. }]
        ),
        "{:?}",
        check.problems
    );
    // In particular the stored object is not called unrecorded.
    assert!(
        !check
            .problems
            .iter()
            .any(|p| matches!(p, Problem::Unrecorded { .. }))
    );
}
