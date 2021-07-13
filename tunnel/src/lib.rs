use tokio_tun;
use anyhow::Result;
use config::{Configuration, Tunnel};
use std::net;
use std::str::FromStr;
pub fn new_tunnel(tun_cfg: &Tunnel, address: String) -> Result<tokio_tun::Tun> {
    let tun = tokio_tun::TunBuilder::new()
    .name(tun_cfg.device_name.as_str())
    .tap(false)
    .packet_info(false)
    .mtu(tun_cfg.mtu)
    .address(net::Ipv4Addr::from_str(address.as_str())?)
    .up()
    .try_build().expect("failed to build tunnel device");
    Ok(tun)
}


 

// the proper way of testing this is to run `cargo test --no-run`
// which builds the test binary which you can then use to run the tests as sudo
#[cfg(test)]
mod tests {
    use super::*;
    use config;
    use tokio;
    #[tokio::test]
    async fn it_works() {
        let tun = new_tunnel(&config::Tunnel::default(), "127.0.0.9".to_string());
        if tun.is_err() {
            println!("failed to build tunne; {:#?}", tun.err());
            assert!(true == false);
            return;
        }
        let tun = tun.unwrap();
        let (mut reader, mut writer) = tokio::io::split(tun);
        drop(writer);
        drop(reader);
    }
}
