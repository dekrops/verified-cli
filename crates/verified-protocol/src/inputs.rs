//! `inputs.json`: the explicit parameters of one evaluation.

use verified_canonical::Value;

use crate::shape::{self, At, Shape};
use crate::time::Instant;

/// The parameters of one evaluation, the same in both protocol versions.
///
/// The evaluation time is `evaluated_at`. Nothing reads a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs<'a> {
    /// The component, whole.
    pub value: &'a Value,
    /// The tenant the evaluation is for.
    pub tenant: &'a str,
    /// When the evidence was ingested.
    pub ingested_at: Instant,
    /// When the evidence set was assembled.
    pub assembled_at: Instant,
    /// The evaluation time.
    pub evaluated_at: Instant,
}

impl<'a> Inputs<'a> {
    pub(crate) fn read(value: &'a Value, at: &At<'_>) -> Shape<Self> {
        let o = shape::object(
            value,
            at,
            &[
                "assembledAt",
                "evaluatedAt",
                "ingestedAt",
                "packageId",
                "tenant",
            ],
        )?;
        shape::uuid(shape::get(o, "packageId"), &at.member("packageId"))?;
        let time = |name| shape::instant(shape::get(o, name), &at.member(name));
        Ok(Self {
            value,
            tenant: shape::wrapped(shape::get(o, "tenant"), &at.member("tenant"))?,
            ingested_at: time("ingestedAt")?,
            assembled_at: time("assembledAt")?,
            evaluated_at: time("evaluatedAt")?,
        })
    }

    /// A member of the component, as JSON. `Null` if there is none.
    #[must_use]
    pub fn member(&self, name: &str) -> &'a Value {
        self.value
            .as_object()
            .and_then(|o| o.get(name))
            .unwrap_or(&Value::Null)
    }
}
