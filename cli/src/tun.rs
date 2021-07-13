use tunnel;
use anyhow::Result;
use config::Configuration;
use utils::channel as channel_utils;
use crossbeam::sync::WaitGroup;
use tokio::task;
use crossbeam_channel::{select, tick};
use signal_hook::{
    consts::{SIGINT, SIGQUIT, SIGTERM},
    iterator::Signals,
};
use tokio::io::AsyncReadExt;

pub fn test_tunnel(matches: &clap::ArgMatches, config_file_path: String) -> Result<()> {
    let config = Configuration::load(config_file_path.as_str())?;
    let ip_addr = matches.value_of("ip-address").unwrap_or("127.0.0.91");
    let tun = tunnel::new_tunnel(&config.tunnel, ip_addr.to_string())?;
    let mut broadcaster: channel_utils::UnboundedBroadcast<bool> = channel_utils::UnboundedBroadcast::new();
    let mut signals =
    Signals::new(vec![SIGINT, SIGTERM, SIGQUIT])?;
    let wg = WaitGroup::new();
    {
        let wg = wg.clone();
        let receiver = broadcaster.subscribe();
        task::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(tun);

            let mut buf = [0u8; 1024];
            loop {
                select! {
                    recv(receiver) -> _msg => {
                        println!("cuaght exit signal from task");
                        break;
                    },
                    default => {
                        let n = reader.read(&mut buf).await;
                        if n.is_err() {
                            println!("failed to read from reader {:#?}", n.err());
                            break;
                        }
                        let n = n.unwrap();
                        println!("reading {} bytes: {:?}", n, &buf[..n]);
                        //writer.write(&buf).await;
                    }
                }
            }
            drop(wg);
        });
    }
    for sig in signals.forever() {
        println!("caught exit signal {}", sig);
        break;
    }
    broadcaster.send(true)?;
    wg.wait();
    Ok(())
}