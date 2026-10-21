// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse`: see `impulse --help` and spec/CLI.md. Results go to stdout and notes to stderr. A
//! refusal prints `impulse: CODE: detail` on stderr and exits with status 1; a usage error exits
//! with status 2.

use clap::Parser;
use impulse_cli::cli::{run, wrpc_connect, Cli, Env};
use impulse_cli::value_cap::MAX_VALUE_ENV;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let max_value = std::env::var_os(MAX_VALUE_ENV);
    let env = Env {
        max_value: max_value.as_deref(),
        connect: &wrpc_connect,
    };
    match run(
        cli,
        &env,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("impulse: {e}");
            ExitCode::from(1)
        }
    }
}
