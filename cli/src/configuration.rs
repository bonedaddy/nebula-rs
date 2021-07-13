use config::Configuration;
use anyhow::Result;

pub fn new_config_file(matches: &clap::ArgMatches, config_file_path: String) -> Result<()> {
    let default = Configuration::default();
    default.save(&config_file_path)?;
    Ok(())
}