// SPDX-License-Identifier: Apache-2.0

//! The guarded call into Cedar: when the engine may be asked, and what its answer is worth.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use serde_json::Value as Json;

/// What one question may weigh, before the engine parses anything.
const MAX_POLICY_BYTES: usize = 1 << 20;
const MAX_SCHEMA_BYTES: usize = 1 << 20;
const MAX_ENTITY_BYTES: usize = 16 << 20;
const MAX_ENTITIES: usize = 10_000;

/// One question, with what the evidence established about it.
pub(crate) struct Question<'a> {
    pub(crate) policies: &'a str,
    pub(crate) schema: &'a str,
    /// Cedar's JSON list of entities.
    pub(crate) entities: Json,
    pub(crate) principal: &'a str,
    pub(crate) action: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) policy_set_in_force: bool,
    pub(crate) entities_complete: bool,
    pub(crate) conflicts: bool,
    pub(crate) language_version: &'a str,
    /// Attributes a source states to have no value, by entity (`type`, `id`).
    pub(crate) absent: BTreeMap<(String, String), BTreeSet<String>>,
}

/// The answer: `Some(true)` allow, `Some(false)` deny, `None` undetermined with reasons.
pub(crate) struct Answer {
    pub(crate) permitted: Option<bool>,
    pub(crate) reasons: BTreeSet<&'static str>,
    pub(crate) determining: Vec<String>,
    pub(crate) errors: Vec<String>,
    pub(crate) details: Vec<String>,
    /// What Cedar itself returned, when it was asked and answered. A diagnostic, never the
    /// outcome.
    pub(crate) engine_decision: Option<&'static str>,
}

/// The engine's language version, as `major.minor`.
pub(crate) fn language_version() -> String {
    let version = cedar_policy::get_lang_version();
    format!("{}.{}", version.major, version.minor)
}

/// The engine this implementation links.
pub(crate) const ENGINE: &str = "cedar-policy 4.10.0 (Rust)";

fn undetermined(found: Vec<(&'static str, String)>) -> Answer {
    Answer {
        permitted: None,
        reasons: found.iter().map(|(code, _)| *code).collect(),
        determining: Vec::new(),
        errors: Vec::new(),
        details: found
            .into_iter()
            .map(|(code, detail)| format!("{code}: {detail}"))
            .collect(),
        engine_decision: None,
    }
}

fn pair(reference: &Json) -> Option<(String, String)> {
    Some((
        reference.get("type")?.as_str()?.to_owned(),
        reference.get("id")?.as_str()?.to_owned(),
    ))
}

fn is_action(kind: &str) -> bool {
    kind == "Action" || kind.ends_with("::Action")
}

/// Every entity a JSON value refers to: `{"__entity": …}` in attribute values and policy
/// expressions, and `"entity": …` in a policy's scope. Actions are the schema's.
fn references(json: &Json, found: &mut BTreeSet<(String, String)>) {
    match json {
        Json::Object(members) => {
            for name in ["__entity", "entity"] {
                if let Some(reference) = members.get(name).and_then(pair)
                    && !is_action(&reference.0)
                {
                    found.insert(reference);
                }
            }
            members.values().for_each(|value| references(value, found));
        }
        Json::Array(values) => values.iter().for_each(|value| references(value, found)),
        _ => {}
    }
}

fn entity_types(schema: &Json) -> impl Iterator<Item = (String, &Json)> {
    schema
        .as_object()
        .into_iter()
        .flatten()
        .flat_map(|(namespace, body)| {
            body.get("entityTypes")
                .and_then(Json::as_object)
                .into_iter()
                .flatten()
                .map(move |(name, definition)| {
                    let qualified = if namespace.is_empty() {
                        name.clone()
                    } else {
                        format!("{namespace}::{name}")
                    };
                    (qualified, definition)
                })
        })
}

fn declares_context(schema: &Json, action: &(String, String)) -> bool {
    schema
        .as_object()
        .into_iter()
        .flatten()
        .any(|(namespace, body)| {
            let kind = if namespace.is_empty() {
                "Action".to_owned()
            } else {
                format!("{namespace}::Action")
            };
            body.get("actions")
                .and_then(Json::as_object)
                .into_iter()
                .flatten()
                .any(|(name, definition)| {
                    let context = definition
                        .get("appliesTo")
                        .and_then(|applies| applies.get("context"));
                    kind == action.0
                        && *name == action.1
                        && context.is_some_and(|context| {
                            !context
                                .get("attributes")
                                .and_then(Json::as_object)
                                .is_some_and(serde_json::Map::is_empty)
                        })
                })
        })
}

fn uid(text: &str) -> Option<EntityUid> {
    EntityUid::from_str(text).ok()
}

fn key(uid: &EntityUid) -> (String, String) {
    (
        uid.type_name().to_string(),
        uid.id().unescaped().to_string(),
    )
}

fn spelled(key: &(String, String)) -> String {
    format!("{}::{}", key.0, Json::String(key.1.clone()))
}

type Failures = Vec<(&'static str, String)>;
type Key = (String, String);

/// Everything the engine and the guards read, parsed.
struct Parsed {
    schema_json: Json,
    list: Vec<Json>,
    schema: Schema,
    policies: PolicySet,
    principal: EntityUid,
    action: EntityUid,
    resource: EntityUid,
    literals: BTreeSet<Key>,
}

/// What can be said without Cedar: the evidence's own account of itself.
fn stated(question: &Question<'_>) -> Failures {
    let mut stated = Vec::new();
    if !question.policy_set_in_force {
        let detail = "the policy set is not shown to be the complete set in force";
        stated.push(("POLICY_SET_NOT_IN_FORCE", detail.to_owned()));
    }
    if question.conflicts {
        stated.push((
            "CONFLICTING_EVIDENCE",
            "accepted records disagree".to_owned(),
        ));
    }
    if question.language_version != language_version() {
        stated.push((
            "ENGINE_NOT_AS_NAMED",
            format!(
                "the profile names Cedar language {}; this engine is {}",
                question.language_version,
                language_version()
            ),
        ));
    }
    stated
}

fn oversized(question: &Question<'_>) -> Failures {
    [
        (question.policies.len() > MAX_POLICY_BYTES, "the policies"),
        (question.schema.len() > MAX_SCHEMA_BYTES, "the schema"),
        (
            question.entities.to_string().len() > MAX_ENTITY_BYTES,
            "the entities",
        ),
    ]
    .into_iter()
    .filter(|(over, _)| *over)
    .map(|(_, what)| {
        (
            "LIMIT_EXCEEDED",
            format!("{what} exceed the size this adapter evaluates"),
        )
    })
    .collect()
}

/// Everything must be readable before any guard is examined.
fn parse(question: &Question<'_>) -> Result<Parsed, String> {
    let schema_json: Json =
        serde_json::from_str(question.schema).map_err(|_| "the schema is not JSON".to_owned())?;
    let list = question
        .entities
        .as_array()
        .ok_or("the entities are not a JSON list")?
        .clone();
    let schema = Schema::from_json_value(schema_json.clone())
        .map_err(|e| format!("the schema is not a Cedar schema: {e}"))?;
    let policies = PolicySet::from_str(question.policies)
        .map_err(|e| format!("the policies do not parse: {e}"))?;
    Entities::from_json_value(question.entities.clone(), None)
        .map_err(|e| format!("the entities do not parse: {e}"))?;
    let principal = uid(question.principal).ok_or("the principal is not an entity identifier")?;
    let action = uid(question.action).ok_or("the action is not an entity identifier")?;
    let resource = uid(question.resource).ok_or("the resource is not an entity identifier")?;
    let mut literals = BTreeSet::new();
    for policy in policies.policies() {
        let json = policy
            .to_json()
            .map_err(|e| format!("the policies cannot be read for entity literals: {e}"))?;
        references(&json, &mut literals);
    }
    Ok(Parsed {
        schema_json,
        list,
        schema,
        policies,
        principal,
        action,
        resource,
        literals,
    })
}

/// G2: validated policies can only fail on a missing entity, an extension or arithmetic.
fn policies_valid(parsed: &Parsed) -> Failures {
    let validation =
        Validator::new(parsed.schema.clone()).validate(&parsed.policies, ValidationMode::Strict);
    if validation.validation_passed() {
        return Vec::new();
    }
    let found: Vec<String> = validation
        .validation_errors()
        .map(ToString::to_string)
        .collect();
    if found.is_empty() {
        // The validator's verdict stands even when it gives no reason.
        return vec![("POLICIES_NOT_VALID", "validation failed".to_owned())];
    }
    found
        .into_iter()
        .map(|e| ("POLICIES_NOT_VALID", e))
        .collect()
}

/// G3: everything a policy can reach must be among the entities, in a complete listing.
fn entities_present(parsed: &Parsed, complete: bool) -> Failures {
    let present: BTreeSet<Key> = parsed
        .list
        .iter()
        .filter_map(|entity| entity.get("uid").and_then(pair))
        .collect();
    let mut reached = BTreeSet::from([key(&parsed.principal), key(&parsed.resource)]);
    for entity in &parsed.list {
        for parent in entity
            .get("parents")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(parent) = pair(parent) {
                reached.insert(parent);
            }
        }
        references(entity.get("attrs").unwrap_or(&Json::Null), &mut reached);
    }
    reached.extend(parsed.literals.iter().cloned());
    let mut failed = Vec::new();
    if !complete {
        let detail = "the entity listing is not declared complete";
        failed.push(("ENTITY_NOT_PRESENT", detail.to_owned()));
    }
    for missing in reached.difference(&present) {
        let detail = format!("{} is not among the entities", spelled(missing));
        failed.push(("ENTITY_NOT_PRESENT", detail));
    }
    failed
}

/// G4: the entities validate, and no declared attribute is absent unless its source says so.
fn entities_valid(parsed: &Parsed, question: &Question<'_>) -> (Failures, Option<Entities>) {
    let declared: BTreeMap<String, BTreeSet<String>> = entity_types(&parsed.schema_json)
        .map(|(name, definition)| {
            let attributes = definition
                .get("shape")
                .and_then(|shape| shape.get("attributes"))
                .and_then(Json::as_object)
                .map(|attributes| attributes.keys().cloned().collect())
                .unwrap_or_default();
            (name, attributes)
        })
        .collect();
    let mut failed = Vec::new();
    let validated = Entities::from_json_value(question.entities.clone(), Some(&parsed.schema));
    if let Err(error) = &validated {
        failed.push(("ENTITIES_NOT_VALID", error.to_string()));
    }
    let none = BTreeSet::new();
    for entity in &parsed.list {
        let reference = entity.get("uid").unwrap_or(&Json::Null);
        let Some(kind) = reference.get("type").and_then(Json::as_str) else {
            let detail = format!("entity identifier {reference} is not {{type, id}}");
            failed.push(("ENTITIES_NOT_VALID", detail));
            continue;
        };
        let held: BTreeSet<&str> = entity
            .get("attrs")
            .and_then(Json::as_object)
            .into_iter()
            .flatten()
            .map(|(name, _)| name.as_str())
            .collect();
        let stated_absent = pair(reference)
            .and_then(|k| question.absent.get(&k))
            .unwrap_or(&none);
        for attribute in declared.get(kind).into_iter().flatten() {
            if !held.contains(attribute.as_str()) && !stated_absent.contains(attribute) {
                let detail = format!("{kind} states no value for '{attribute}'");
                failed.push(("ENTITIES_NOT_VALID", detail));
            }
        }
    }
    (failed, validated.ok())
}

/// The supported subset: no request context, no templates or links, no tags.
fn unsupported(parsed: &Parsed) -> Failures {
    let mut failed = Vec::new();
    if declares_context(&parsed.schema_json, &key(&parsed.action)) {
        let detail = format!(
            "the schema declares a request context for {}; none is evaluated",
            parsed.action
        );
        failed.push(("CONTEXT_NOT_SUPPORTED", detail));
    }
    if parsed.policies.templates().next().is_some() {
        let detail = "policy templates and links are not evaluated";
        failed.push(("FEATURE_NOT_SUPPORTED", detail.to_owned()));
    }
    let declares_tags =
        entity_types(&parsed.schema_json).any(|(_, definition)| definition.get("tags").is_some());
    let carries_tags = parsed
        .list
        .iter()
        .any(|entity| entity.get("tags").is_some_and(|tags| !tags.is_null()));
    if declares_tags || carries_tags {
        failed.push((
            "FEATURE_NOT_SUPPORTED",
            "entity tags are not evaluated".to_owned(),
        ));
    }
    if parsed.list.len() > MAX_ENTITIES {
        let detail = format!("more than {MAX_ENTITIES} entities are not evaluated");
        failed.push(("LIMIT_EXCEEDED", detail));
    }
    failed
}

/// Ask the engine. Its answer is used only when it reports no evaluation error.
fn ask(parsed: Parsed, entities: &Entities) -> Answer {
    let Parsed {
        schema,
        policies,
        principal,
        action,
        resource,
        ..
    } = parsed;
    let request = match Request::new(principal, action, resource, Context::empty(), Some(&schema)) {
        Ok(request) => request,
        Err(error) => return undetermined(vec![("EVALUATION_ERROR", error.to_string())]),
    };
    let response = Authorizer::new().is_authorized(&request, &policies, entities);
    let mut determining: Vec<String> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    determining.sort();
    let errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect();
    let allowed = response.decision() == Decision::Allow;
    let engine_decision = Some(if allowed { "Allow" } else { "Deny" });
    if errors.is_empty() {
        return Answer {
            permitted: Some(allowed),
            reasons: BTreeSet::new(),
            determining,
            errors,
            details: Vec::new(),
            engine_decision,
        };
    }
    // An errored policy was skipped. It may have been the one that decides.
    Answer {
        permitted: None,
        reasons: BTreeSet::from(["EVALUATION_ERROR"]),
        determining,
        details: errors
            .iter()
            .map(|e| format!("EVALUATION_ERROR: {e}"))
            .collect(),
        errors,
        engine_decision,
    }
}

/// Cedar is asked only when every guard holds. Everything else is undetermined, never a denial.
pub(crate) fn authorize(question: &Question<'_>) -> Answer {
    let mut failed = stated(question);
    let oversized = oversized(question);
    if !oversized.is_empty() {
        failed.extend(oversized);
        return undetermined(failed);
    }
    let parsed = match parse(question) {
        Ok(parsed) => parsed,
        Err(detail) => {
            failed.push(("INPUT_UNREADABLE", detail));
            return undetermined(failed);
        }
    };
    failed.extend(policies_valid(&parsed));
    failed.extend(entities_present(&parsed, question.entities_complete));
    let (invalid, entities) = entities_valid(&parsed, question);
    failed.extend(invalid);
    failed.extend(unsupported(&parsed));
    match entities {
        Some(entities) if failed.is_empty() => ask(parsed, &entities),
        _ => undetermined(failed),
    }
}
