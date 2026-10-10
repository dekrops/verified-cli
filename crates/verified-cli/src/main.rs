// SPDX-License-Identifier: Apache-2.0

//! `verified`: Git-like tools for verifiable work.
//!
//! This binary parses arguments, reads files and prints. Every protocol rule
//! lives in the library crates.

mod cli;
mod exit;
mod input;
mod render;
mod trace;
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
    };
    code.into()
}
