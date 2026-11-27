//! Vetted addresses are the addresses consumed by reqwest, without a second lookup.
//! ref: reqwest 0.12.28 src/dns/resolve.rs (Resolve / Addrs).
use crate::EgressDenied;
use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub(crate) fn private_network(network: IpNet) -> bool {
    network == network.trunc()
        && ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
            .iter()
            .any(|parent| parent.parse::<IpNet>().unwrap().contains(&network))
}

pub(crate) fn allowed(ip: IpAddr, loopback: bool, cidrs: &[IpNet]) -> bool {
    if loopback && ip.is_loopback() {
        return true;
    }
    if cidrs.iter().any(|network| network.contains(&ip)) {
        return true;
    }
    let blocked: &[&str] = match ip {
        IpAddr::V4(_) => &[
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
        ],
        IpAddr::V6(_) => {
            if !"2000::/3".parse::<ipnet::IpNet>().unwrap().contains(&ip) {
                return false;
            }
            &["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
        }
    };
    !blocked
        .iter()
        .any(|net| net.parse::<ipnet::IpNet>().unwrap().contains(&ip))
}

struct SystemResolver;
impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            Ok(Box::new(addresses.collect::<Vec<_>>().into_iter()) as Addrs)
        })
    }
}
pub(crate) struct VettedResolver {
    lookup: Arc<dyn Resolve>,
    loopback: bool,
    cidrs: Vec<IpNet>,
}
impl VettedResolver {
    #[cfg(test)]
    pub(crate) fn with_lookup(mut self, lookup: Arc<dyn Resolve>) -> Self {
        self.lookup = lookup;
        self
    }
    pub(crate) fn new(loopback: bool, cidrs: Vec<IpNet>) -> Self {
        Self {
            lookup: Arc::new(SystemResolver),
            loopback,
            cidrs,
        }
    }
}
impl Resolve for VettedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let pending = self.lookup.resolve(name);
        let loopback = self.loopback;
        let cidrs = self.cidrs.clone();
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = pending.await?.collect();
            if addresses.is_empty() || addresses.iter().any(|a| !allowed(a.ip(), loopback, &cidrs))
            {
                return Err(Box::new(EgressDenied) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Answers(Vec<SocketAddr>);
    impl Resolve for Answers {
        fn resolve(&self, _: Name) -> Resolving {
            let result = self.0.clone();
            Box::pin(async move { Ok(Box::new(result.into_iter()) as Addrs) })
        }
    }
    #[tokio::test]
    async fn mixed_empty_and_rebound_dns_fail_closed() {
        for answers in [
            vec![],
            vec!["8.8.8.8:0", "127.0.0.1:0"],
            vec!["8.8.8.8:0", "[fd00::1]:0"],
            vec!["169.254.169.254:0"],
        ] {
            let resolver = VettedResolver {
                lookup: Arc::new(Answers(
                    answers.iter().map(|a| a.parse().unwrap()).collect(),
                )),
                loopback: false,
                cidrs: vec![],
            };
            assert!(resolver.resolve("idp.test".parse().unwrap()).await.is_err());
        }
        let addresses = vec![
            "8.8.8.8:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];
        let resolver = VettedResolver {
            lookup: Arc::new(Answers(addresses.clone())),
            loopback: false,
            cidrs: vec![],
        };
        assert_eq!(
            resolver
                .resolve("idp.test".parse().unwrap())
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            addresses
        );
    }
    #[test]
    fn reserved_and_encoded_addresses_are_not_public() {
        for address in [
            "0.0.0.0",
            "127.1.2.3",
            "169.254.169.254",
            "10.0.0.1",
            "100.64.0.1",
            "172.31.1.1",
            "192.168.0.1",
            "198.19.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(!allowed(address.parse().unwrap(), false, &[]), "{address}");
        }
        assert!(allowed("127.0.0.1".parse().unwrap(), true, &[]));
        assert!(!allowed("10.0.0.1".parse().unwrap(), true, &[]));
    }
    #[tokio::test]
    async fn private_dns_checks_every_answer_and_preserves_vetted_addresses() {
        for (answers, accepted) in [
            (vec!["10.42.0.9:0", "[fd12::9]:0"], true),
            (vec!["10.42.0.9:0", "8.8.8.8:0"], true),
            (vec!["10.42.0.9:0", "10.42.0.10:0"], false),
            (vec!["10.42.0.9:0", "169.254.169.254:0"], false),
            (vec!["127.0.0.1:0"], false),
        ] {
            let addresses = answers
                .iter()
                .map(|v| v.parse().unwrap())
                .collect::<Vec<_>>();
            let resolver = VettedResolver {
                lookup: Arc::new(Answers(addresses.clone())),
                loopback: false,
                cidrs: vec![
                    "10.42.0.9/32".parse().unwrap(),
                    "fd12::9/128".parse().unwrap(),
                ],
            };
            let result = resolver.resolve("idp.test".parse().unwrap()).await;
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                assert_eq!(result.unwrap().collect::<Vec<_>>(), addresses);
            }
        }
    }
}
