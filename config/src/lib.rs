use core::slice::SlicePattern;

use serde::{Serialize, Deserialize};
use anyhow::Result;

/// the main configuration object
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Configuration {
    pub pki: PKI,
    pub listen: Listen,
    pub punchy: Punchy,
    pub lighthouse: LightHouse,
    pub tunnel: Tunnel,
    pub static_host_map: StaticHostMap,
}

/// defines the location of credentials for this node
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PKI {
    /// CAs for which this node accepts issued certificates
    pub ca_cert: String,
    pub node_cert: String,
    pub node_key: String,
}

/// defines information about which host and port
/// the node will listen on
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Listen {
    /// todo(bonedaddy): support ipv6
    pub host: String,
    /// for roaming nodes you should set this to 0
    pub port: i32,
    // max number of packets to pull from kernel for each syscall
    // default 64
    pub batch: i32,
    // default 10485760
    pub read_buffer: i64,
    // default 10485760
    pub write_buffer: i64,
}

/// provides information about the configuration used for NAT hole punching
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Punchy {
    /// if true punch inbound/outbound at regular intervals to avoid firewall nat mapping expiration
    pub punch: bool,
    /// if true a node you are trying to reach will connect back to you if your hole punching fails
    /// useful if a node is behind a difficult nat (ie symmetric nat)
    // default is false
    pub respond: bool,
    // delays a punch response for misbehaving nats, default is 1second
    // respond must be true to take effect
    pub delay: i32,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LightHouse {
    /// indicates if this node is a lighthouse which enables lighthouse functionality
    pub am_lighthouse: bool,
    /// the number of seconds between updates from this node to a lighthouse
    pub interval: i64,
    /// a list of lighthouses this node should report to and query from
    /// this should be empty on lighthouse nodes and not empty on non lighthouse nodes
    pub hosts: Vec<String>,
    // todo(bonedaddy): add remote allow list https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/examples/config.yml#L50
    // todo(bonedaddy): add local allow list https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/examples/config.yml#L67    

}

/// provides information about the confguration of the tun device
/// address is set in the nebula certificate the node is issued
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tunnel {
    pub disabled: bool,
    pub device_name: String,
    pub drop_local_broadcast: bool,
    pub drop_multicast: bool,
    pub tx_queue: i32,
    pub mtu: i32,
    pub safe_routes: Option<Vec<SafeRoute>>,
    pub unsafe_routes: Option<Vec<UnsafeRoute>>,

}

/// provides route based MTU overrides for known vpn ip paths
/// that can suppor larger MTUs
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SafeRoute {
    pub mtu: i32,
    pub route: String,
}

/// allows you to route traffic over nebula to non-nebula nodes
/// should be avoided unless you have hosts/services that cant run nebula
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnsafeRoute {
    pub mtu: i32,
    pub route: String,
    pub via: String,
}


/// a set of hosts with fixed ip addresses that will not change
/// all addresses define here will be used by nebula when attempting to establish a tunnel
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StaticHostMap {
    pub hosts: Vec<StaticHost>,
}

/// hosts with fixed ip addresses, generally speaking
/// tehse are only for lighthouse nodes
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StaticHost {
    /// the ip address of the host on nebula
    pub nebula_ip: String,
    /// actual non nebula ip addresses
    pub real_ips: Vec<String>,
}


impl Configuration {
    pub fn save(&self, path: &str, as_json: bool) -> Result<()> {
        let s = serde_yaml::to_string(self)?;
        std::fs::write(path, s)?;
        Ok(())
    }
    pub fn load(path: &str, from_json: bool) -> Result<Configuration> {
        let data = std::fs::read(path)?;
        let config: Configuration = serde_yaml::from_slice(data.as_slice())?;
        Ok(config)
    }
}

// todo(bonedaddy): implement local range https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/examples/config.yml#L117
impl Default for Configuration {
    fn default() -> Self {
        Self {
            pki: PKI {
                ca_cert: "/etc/nebula/ca.crt".to_string(),
                node_cert: "/etc/nebula/node.crt".to_string(),
                node_key: "/etc/nebula/node.key".to_string(),
            },
            listen: Listen {
                host: "127.0.0.1".to_string(),
                port: 4243,
                batch: 64,
                read_buffer: 10485760,
                write_buffer: 10485760,
            },
            punchy: Punchy {
                punch: true,
                respond: false,
                delay: 0,
            },
            lighthouse: LightHouse{
                am_lighthouse: true,
                interval: 60,
                hosts: [].into(),
            },
            tunnel: Tunnel {
                disabled: false,
                device_name: "nebula-1".to_string(),
                drop_local_broadcast: false,
                drop_multicast: false,
                tx_queue: 500,
                mtu: 1300,
                safe_routes: None,
                unsafe_routes: None,
            },
            static_host_map: StaticHostMap{
                hosts: [StaticHost{
                    nebula_ip: "172.16.254.1".to_string(),
                    real_ips: ["127.0.0.1:4243".to_string()].into(),
                }].into()
            }
        }
    }
}




#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
