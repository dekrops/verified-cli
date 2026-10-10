//! The two evidence components, which describe the same statements.

use verified_canonical::Value;

use crate::container::ShapeProblem;
use crate::shape::{self, At, Shape};
use crate::statement::SignedStatement;

/// A signed statement together with the body it is said to commit to.
///
/// That the body is the one the statement's payload commits to is an
/// admission check, not a shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence<'a, B> {
    /// The signed statement.
    pub statement: SignedStatement<'a>,
    /// The body's JSON, whole: the payload commits to its canonical text.
    pub body_value: &'a Value,
    /// The body, read.
    pub body: B,
}

/// Reads `evidence/bodies.json` and `evidence/statements.json`: one
/// `{ id, body }` per signed statement, carrying the same identifiers in the
/// same, ascending order.
pub(crate) fn read<'a, B>(
    bodies: &'a Value,
    statements: &'a Value,
    body: impl Fn(&'a Value, &At<'_>) -> Shape<B>,
) -> Shape<Vec<Evidence<'a, B>>> {
    let bodies_at = At::root("evidence/bodies.json");
    let statements_at = At::root("evidence/statements.json");
    let bodies = shape::each(bodies, &bodies_at, |entry, at| {
        let o = shape::object(entry, at, &["body", "id"])?;
        let id = shape::uuid(shape::get(o, "id"), &at.member("id"))?;
        let value = shape::get(o, "body");
        Ok((id, value, body(value, &at.member("body"))?))
    })?;
    let statements = shape::each(statements, &statements_at, SignedStatement::read)?;
    if !bodies
        .iter()
        .map(|(id, ..)| *id)
        .eq(statements.iter().map(|s| s.id))
    {
        return statements_at.fail(ShapeProblem::Inconsistent(
            "does not carry the same identifiers, in the same order, as evidence/bodies.json",
        ));
    }
    if !statements.windows(2).all(|w| w[0].id <= w[1].id) {
        return statements_at.fail(ShapeProblem::Inconsistent(
            "is not in ascending order of evidence identifier",
        ));
    }
    Ok(statements
        .into_iter()
        .zip(bodies)
        .map(|(statement, (_, body_value, body))| Evidence {
            statement,
            body_value,
            body,
        })
        .collect())
}
