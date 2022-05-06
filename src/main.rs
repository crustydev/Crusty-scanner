use std::env;

use anyhow::Result;
use clap::{App, Arg, SubCommand};

mod core;
mod scanners;
mod utils;
mod ports_list;

fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info, trust_dns_proto=error");
    env_logger::init();

    println!("Welcome to crusty_scanner!");
    core::help();

    let cli = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .subcommand(SubCommand::with_name("scanners").about("List scanner modules"))
        .subcommand(SubCommand::with_name("about").about("Provide details on program"))
        .subcommand(SubCommand::with_name("help").about("Details of use"))
        .subcommand(
            SubCommand::with_name("scan").about("Scan a target domain").arg(
                Arg::with_name("target")
                    .help("domain to be scanned")
                    .required(true)
                    .index(1)
            ),
        )
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .setting(clap::AppSettings::VersionlessSubcommands)
        .get_matches();

    if let Some(_) = cli.subcommand_matches("scanners") {
        core::list_scanners();
    } else if let Some(_) = cli.subcommand_matches("about") {
        core::about();
    } else if let Some(_) = cli.subcommand_matches("help") {
        core::help();
    } else if let Some(matches) = cli.subcommand_matches("scan") {
        let target = matches.value_of("target").unwrap();
        core::scan(target)?;
    }

    Ok(())

}