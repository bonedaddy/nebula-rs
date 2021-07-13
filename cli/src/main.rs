use clap::{App, Arg, SubCommand};
use anyhow::{Result, anyhow};

mod configuration;
mod tun;


#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("nebula-rs")
    .about("rust client for the nebula overlay protocol")
    .author("Bonedaddy <catch@bonedaddy.io>")
    .arg(
        Arg::with_name("config")
        .short("c")
        .long("config")
        .value_name("FILE")
        .help("path to configuration file")
    )
    .subcommand(
        SubCommand::with_name("config")
        .about("configuration management commands")
        .subcommands(
            vec![
                SubCommand::with_name("new")
                .about("generate a new configuration file")
            ]
        )
    )
    .subcommand(
        SubCommand::with_name("tunnel")
        .about("tunnel management commands")
        .subcommands(
            vec![
                SubCommand::with_name("test")
                .about("test tunnel command, opens a tunnel and listens for data")
                .arg(
                    Arg::with_name("ip-addr")
                    .short("i")
                    .long("ip-addr")
                    .value_name("IP")
                )
            ]
        )
    )
    .get_matches();

    let config = matches.value_of("config").unwrap_or("config.yaml");

    process_matches(&matches, config.to_string()).await?;

    Ok(())
}


async fn process_matches<'a>(matches: &clap::ArgMatches<'a>, config_file_path: String) -> Result<()> {
    match matches.subcommand() {
        ("config", Some(config)) => match config.subcommand() {
            ("new", Some(new_config)) => 
                configuration::new_config_file(new_config, config_file_path),
            _ => no_match("config"),
        }
        ("tunnel", Some(tunnel)) => match tunnel.subcommand() {
            ("test", Some(test_tunnel)) => {
                tun::test_tunnel(test_tunnel, config_file_path)
            }
            _ => no_match("tunnel")
        }
        _ => no_match(""),
    }
}


fn no_match(command_group: &str) -> Result<()> {
    Err(anyhow!("invalid {} command found, please run --help for more information", command_group).into())
}