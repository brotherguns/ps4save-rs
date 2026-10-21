mod cli;

#[cfg(feature = "gui")]
mod gui;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::generate;

use cli::{Cli, Command};
use ps4save_rs::commands::{run_decrypt, run_keystone, run_encrypt, inspect_path, list_path, reregion_from_paths, run_resign, run_selftest};
use ps4save_rs::settings::Settings;

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.gui {
        #[cfg(feature = "gui")]
        {
            if let Err(e) = gui::run() {
                eprintln!("GUI error: {e}");
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        #[cfg(not(feature = "gui"))]
        {
            eprintln!("built without GUI support");
            return ExitCode::FAILURE;
        }
    }

    let command = match cli.command {
        Some(c) => c,
        None => {
            eprintln!("usage: ps4save-rs [--gui] <command>");
            eprintln!("commands: check-config, selftest, inspect-save, list, decrypt, encrypt, resign, reregion");
            return ExitCode::FAILURE;
        }
    };

    if let Command::Completions { shell } = command {
        generate(shell, &mut Cli::command(), "ps4save-rs", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }

    let settings = Settings::load();
    let cfg = &settings.config_path;

    match command {
        Command::Completions { .. } => unreachable!(),
        Command::CheckConfig => match ps4save_rs::config::Config::load(cfg) {
            Ok(c) => {
                println!(
                    "loaded {cfg}: {} sealed enc, {} sealed sign, {} sd content, {} ekpfs obf, {} title sections",
                    c.common.sealed_key_enc.iter().filter(|k| k.is_some()).count(),
                    c.common.sealed_key_sign.iter().filter(|k| k.is_some()).count(),
                    c.common.sd_content_key.iter().filter(|k| k.is_some()).count(),
                    c.common.ekpfs_obf_key.iter().filter(|k| k.is_some()).count(),
                    c.titles.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Command::Selftest { version } => match run_selftest(cfg, version) {
            Ok(()) => {
                println!("selftest ok (sealed key v{version} encrypt/decrypt roundtrip)");
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Command::InspectSave { save } => {
            match inspect_path(cfg, &save) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::List { save } => {
            match list_path(cfg, &save) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::Decrypt { save, outdir } => {
            match run_decrypt(cfg, &save, outdir.as_deref()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::Encrypt {
            input,
            out,
            ekpfs,
            seed,
            blocks,
            compress,
        } => {
            match run_encrypt(cfg, &input, out.as_deref(), ekpfs.as_deref(), seed.as_deref(), blocks, compress) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::Keystone { save, outfile } => {
            match run_keystone(cfg, &save, outfile.as_deref()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::Resign {
            save,
            account_id,
            out,
            compress,
        } => {
            let account_id = account_id.unwrap_or_default();
            match run_resign(cfg, &save, &account_id, out.as_deref(), compress) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
        Command::Reregion {
            src,
            sample,
            account_id,
            out,
            compress,
        } => {
            match reregion_from_paths(
                cfg,
                &src,
                &sample,
                account_id.as_deref(),
                out.as_deref(),
                compress,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
    }
}

fn fail(e: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::FAILURE
}
