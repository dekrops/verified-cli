// SPDX-License-Identifier: Apache-2.0

//! `verified`: Git-like tools for verifiable work.
//!
//! This binary parses arguments, reads files and prints. Every protocol rule
//! lives in the library crates.

mod cli;
mod evidence;
mod exit;
mod input;
mod issue;
mod portable;
mod registration;
mod render;
mod trace;
mod trust;
mod verify;
mod workspace;

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let args = cli::Args::parse();
    let mut out = render::Output::new(&args.global);
    let code = match &args.command {
        cli::Command::Verify(command) => verify::run(command, &mut out),
        cli::Command::Init(command) => workspace::init(command, &mut out),
        cli::Command::Import(command) => workspace::import(command, &mut out),
        cli::Command::Show(command) => workspace::show(command, &mut out),
        cli::Command::Log(_) => workspace::log(&mut out),
        cli::Command::Trace(command) => trace::run(command, &mut out),
        cli::Command::Fsck(_) => workspace::fsck(&mut out),
        cli::Command::Export(command) => portable::export(command, &mut out),
        cli::Command::Diff(command) => portable::diff(command, &mut out),
        cli::Command::Replay(command) => portable::replay(command, &mut out),
        cli::Command::Registration(cli::Registration::Verify(command)) => {
            registration::verify(command, &mut out)
        }
        cli::Command::Registration(cli::Registration::Log(command)) => {
            registration::log(command, &mut out)
        }
        cli::Command::Registration(cli::Registration::Audit(command)) => {
            registration::audit(command, &mut out)
        }
        cli::Command::Registration(cli::Registration::Unit(command)) => {
            registration::unit(command, &mut out)
        }
        cli::Command::Evidence(cli::Evidence::Chain(command)) => evidence::chain(command, &mut out),
        cli::Command::Trust(cli::TrustCommand::Init(command)) => trust::init(command, &mut out),
        cli::Command::Trust(cli::TrustCommand::Add(command)) => trust::add(command, &mut out),
        cli::Command::Trust(cli::TrustCommand::Revoke(command)) => trust::revoke(command, &mut out),
        cli::Command::Trust(cli::TrustCommand::Show(command)) => trust::show(command, &mut out),
        cli::Command::Issue(command) => issue::issue(command, &mut out),
        cli::Command::Sign(command) => issue::sign(command, &mut out),
    };
    code.into()
}
