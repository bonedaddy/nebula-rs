use cidr_radix;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use ipnet::{Ipv4Net, Ipv6Net, IpNet};
use std::str::FromStr;

/// an implementation of CIDRTree specifying ip address which are allowed
/// aka addressed not included in the cidr tree
pub struct AllowList {
    // any addresses included in this are not allowed
    cidr_tree: cidr_radix::CIDRTree,
}


impl AllowList {
    pub fn new() -> Self {
        Self{
            cidr_tree: cidr_radix::CIDRTree::new(),
        }
    }
    pub fn blacklist_cidr(&mut self, net: IpNet) {
        self.cidr_tree.add_cidr(net);
    }
    pub fn allowed(&self, net: IpNet) -> bool {
        let allowed = self.cidr_tree.contains(net);
        allowed == false
    }
    pub fn v4_iter(&self) -> iprange::IpRangeIter<Ipv4Net> {
        self.cidr_tree.v4_iter()
    }
    pub fn v6_iter(&self) -> iprange::IpRangeIter<Ipv6Net> {
        self.cidr_tree.v6_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_allow_list() {
        let mut allow_list = AllowList::new();
        allow_list.blacklist_cidr(IpNet::from_str("1.0.0.0/8").unwrap());
        assert!(allow_list.allowed(IpNet::from_str("1.0.0.0/8").unwrap()) == false);
        assert!(allow_list.allowed(IpNet::from_str("2.1.0.0/16").unwrap()) == true);
        allow_list.blacklist_cidr(IpNet::from_str("4.1.1.1/32").unwrap());
        assert!(allow_list.allowed(IpNet::from_str("4.1.1.1/32").unwrap()) == false);
        assert!(allow_list.allowed(IpNet::from_str("4.1.1.1/30").unwrap()) == true);
        assert!(allow_list.allowed(IpNet::from_str("4.1.1.1/24").unwrap()) == true);
        allow_list.blacklist_cidr(IpNet::from_str("4.1.1.1/24").unwrap());
        assert!(allow_list.allowed(IpNet::from_str("4.1.1.1/30").unwrap()) == false);
        assert!(allow_list.allowed(IpNet::from_str("4.1.1.1/24").unwrap()) == false);
        for _net in allow_list.v4_iter() {
        
        }
        for _net in allow_list.v6_iter() {

        }
    }
}
