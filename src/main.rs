use clap::Parser;
use rewind::{
    cli::{Action, Cli},
    history::supervisor::CANCELLED,
};
use std::sync::atomic::Ordering;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = execute(cli.command) {
        eprintln!("rewind: {error:#}");
        std::process::exit(1);
    }
}

fn execute(action: Action) -> rewind::Result<()> {
    if let Action::Worker { socket } = action {
        return rewind::history::worker::run(&socket);
    }
    ctrlc::set_handler(|| CANCELLED.store(true, Ordering::Relaxed))?;
    match action {
        Action::Recover(args) => rewind::cli::recover(args),
        Action::Replay(args) => rewind::cli::replay_args(args),
        Action::Worker { .. } => unreachable!(),
    }
}
