use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use iprange::IpRange;
use ipnet::{Ipv4Net, Ipv6Net, IpNet};
use std::sync::RwLock;
use anyhow::Result;
use std::str::FromStr;

#[derive(Debug, Default)]
pub struct CIDRTree {
    cidr4: iprange::IpRange<Ipv4Net>,
    cidr6: iprange::IpRange<Ipv6Net>,
}


impl CIDRTree {
    pub fn new() -> Self {
        Self{
            cidr4: iprange::IpRange::new(),
            cidr6: iprange::IpRange::new(),
        }
    }
    pub fn add_cidr(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4net) => self.add_v4(v4net),
            IpNet::V6(v6net) => self.add_v6(v6net),
        }
    }
    pub fn contains(&self, net: IpNet) -> bool {
        match net {
            IpNet::V4(v4net) => self.contains_v4(&v4net),
            IpNet::V6(v6net) => self.contains_v6(&v6net),
        }
    }
    pub fn v4_iter(&self) -> iprange::IpRangeIter<Ipv4Net> {
        self.cidr4.iter()
    }
    pub fn v6_iter(&self) -> iprange::IpRangeIter<Ipv6Net> {
        self.cidr6.iter()
    }
    fn add_v4(&mut self, net: Ipv4Net) {
        self.cidr4.add(net);
    }
    fn add_v6(&mut self, net: Ipv6Net) {
        self.cidr6.add(net);
    }
    fn contains_v4(&self, net: &Ipv4Net) -> bool {
        self.cidr4.contains(net)
    }
    fn contains_v6(&self, net: &Ipv6Net) -> bool {
        self.cidr6.contains(net)
    }
}


impl Clone for CIDRTree {
    fn clone(&self) -> Self {
        Self{
            cidr4: self.cidr4.clone(),
            cidr6: self.cidr6.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cidr_tree_new() {
        let _tree = CIDRTree::new();
    }
    #[test]
    pub fn test_add_nets() {
        let mut tree = CIDRTree::new();
        assert!(tree.cidr4.is_empty() == true);
        assert!(tree.cidr6.is_empty() == true);
        tree.add_cidr(IpNet::from_str("1.0.0.0/8").unwrap());
        assert!(tree.cidr4.is_empty() == false);
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("2.1.0.0/16").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("3.1.1.0/24").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("4.1.1.1/24").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("4.1.1.1/30").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("4.1.1.1/32").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("254.0.0.0/4").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == false);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == false);
        tree.add_cidr(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap());
        assert!(tree.cidr6.is_empty() == false);
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == true);
        tree.add_cidr(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == true);
        tree.add_cidr(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap());
        assert!(tree.contains(IpNet::from_str("1.0.0.0/8").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("3.1.1.0/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("4.1.1.1/32").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("254.0.0.0/4").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/64").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/80").unwrap()) == true);
        assert!(tree.contains(IpNet::from_str("1:2:0:4:5:0:0:0/96").unwrap()) == true);
        // todo(bonedaddy): eventually add more specific iter testing
        for _net in tree.v4_iter() {
        
        }
        for _net in tree.v6_iter() {

        }
    }

}
