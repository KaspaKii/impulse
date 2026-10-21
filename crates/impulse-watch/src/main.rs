// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse-watch`: see spec/WATCH.md, "The binary". Events are one JSON object per line on
//! stdout; diagnostics and refusals (`impulse-watch: CODE: detail`) are on stderr. Exit 0 when
//! a bounded run polled without a failure, 1 for a refusal or a failed poll, 2 for a usage error.

use clap::Parser;
use impulse_watch::cli::{Cli, Command};
use impulse_watch::run::{fatal_line_in, run, run_probe};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = match &cli.command {
        Command::Run(args) => args.log_format,
        Command::Probe(args) => args.log_format,
    };
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let result = match &cli.command {
        Command::Run(args) => run(args, &mut out, &mut err)
            .await
            .map(|o| o.failed_polls == 0),
        Command::Probe(args) => run_probe(args, &mut out).await.map(|()| true),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("{}", fatal_line_in(format, &e));
            ExitCode::FAILURE
        }
    }
}
