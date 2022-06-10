use crate::port::Port;
use crate::TricoderError;

use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use reqwest::blocking::Client;
use serde::Deserialize;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Subdomain {
    domain: String,
    open_ports: Vec<Port>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CrtShEntry {
    name_value: String,
}

impl Subdomain {
    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn open_ports(&self) -> &[Port] {
        &self.open_ports
    }

    pub fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Self>, TricoderError> {
        let entries: Vec<CrtShEntry> = http_client
            .get(&format!("https://crt.sh/?q=%25.{}&output=json", target))
            .send()?
            .json()?;

        let mut subdomains: HashSet<String> = entries
            .into_iter()
            .flat_map(|entry| {
                entry
                    .name_value
                    .split('\n')
                    .map(|subdomain| subdomain.trim().to_string())
                    .collect::<Vec<String>>()
            })
            .filter(|subdomain: &String| subdomain != target)
            .filter(|subdomain: &String| !subdomain.contains('*'))
            .collect();

        subdomains.insert(target.to_string());

        let subdomains = subdomains
            .into_iter()
            .map(|domain| Subdomain {
                domain,
                open_ports: Vec::new(),
            })
            .filter(Subdomain::resolves)
            .collect();

        Ok(subdomains)
    }

    pub fn resolves(&self) -> bool {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(4);
        let dns_resolver = Resolver::new(ResolverConfig::default(), opts)
            .expect("subdomain resolver: building DNS client");
        dns_resolver.lookup_ip(self.domain.as_str()).is_ok()
    }

    pub fn scan_ports(&mut self) {
        let socket_addresses: Vec<SocketAddr> = format!("{}:1024", self.domain)
            .to_socket_addrs()
            .expect("port scanner: Creating socket address")
            .collect();

        if !socket_addresses.is_empty() {
            self.open_ports = crate::MOST_COMMON_PORTS_100
                .into_par_iter()
                .map(|&port| {
                    let mut first_socket_address = socket_addresses[0];
                    first_socket_address.set_port(port);
                    Port::scan(socket_addresses[0])
                })
                .filter(Port::is_open)
                .collect();
        }
    }
}
