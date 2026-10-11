// SPDX-License-Identifier: Apache-2.0

//! The contract language: reading a contract and evaluating it.
//!
//! Input: a contract on the first line, then an environment
//! (`{ inputs, facts, complete }`).
//!
//! Beyond not panicking: evaluation is a function of its input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verified_contract::Contract;
use verified_fuzz::{head, json};

fuzz_target!(|data: &[u8]| {
    let (contract, environment) = head(data);
    let Some(Ok(contract)) = json(contract).map(|contract| Contract::read(&contract)) else {
        return;
    };
    let Some(environment) = json(environment) else {
        return;
    };
    let outcome = contract.evaluate(&environment);
    assert_eq!(
        outcome
            .as_ref()
            .map(|outcome| outcome.to_value())
            .map_err(Clone::clone),
        contract
            .evaluate(&environment)
            .map(|outcome| outcome.to_value()),
        "evaluation is not repeatable"
    );
});
