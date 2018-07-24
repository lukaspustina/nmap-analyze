use mapping::{self, Mapping};
use nmap::{self, Run};
use whitelist::{self, Whitelists};

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, PartialEq)]
pub enum AnalysisResult {
    Pass,
    Fail,
    Error,
}

#[derive(Debug, PartialEq)]
pub enum PortAnalysisResult {
    Pass(u16),
    Fail(u16),
    Unknown(u16),
}

pub struct Analyzer<'a> {
    scanned_host_by_ip: HashMap<&'a IpAddr, &'a nmap::Host>,
    whitelist_by_ip: HashMap<&'a IpAddr, &'a whitelist::Whitelist>,
}

impl<'a> Analyzer<'a> {
    /// TODO: Currently, there is no error handling for an IP that cannot be mapped to a whitelist.
    pub fn new<'b>(nmap_run: &'b Run, mapping: &'b Mapping, whitelists: &'b Whitelists) -> Analyzer<'b> {
        let scanned_host_by_ip = run_to_scanned_hosts_by_ip(&nmap_run);
        let whitelist_by_ip = whitelist_by_ip(&mapping, &whitelists);

        Analyzer {
            scanned_host_by_ip,
            whitelist_by_ip,
        }
    }

    pub fn analyze(&self) -> Vec<AnalysisResult> {
        self.scanned_host_by_ip.iter().map( |(ip, host)| {
            // TODO Add error for host w/o corresponding whitelist
            let wl = self.whitelist_by_ip.get(ip).unwrap();
            analyze_host(ip, host, wl)
        }).collect()
    }
}

fn run_to_scanned_hosts_by_ip(nmap_run: &Run) -> HashMap<&IpAddr, &nmap::Host> {
    let mut shbi = HashMap::new();
    for host in &nmap_run.hosts {
        shbi.insert(&host.address.addr, host);
    }

    shbi
}

fn whitelist_by_ip<'a>(mapping: &'a Mapping, whitelist: &'a Whitelists) -> HashMap<&'a IpAddr, &'a whitelist::Whitelist> {
    let wls = whitelists_to_whitelist_by_name(whitelist);
    let mut wbi = HashMap::new();

    for m in mapping {
        let key: &str = &m.whitelist;
        let wl = wls.get(key).unwrap(); // TODO: Error handling
        wbi.insert(&m.ip, *wl);
    }

    wbi
}

fn whitelists_to_whitelist_by_name(whitelists: &Whitelists) -> HashMap<&str, &whitelist::Whitelist> {
    let mut wbn = HashMap::new();
    for wl in &whitelists.whitelists {
        wbn.insert(wl.name.as_ref(), wl);
    }

    wbn
}

fn analyze_host(ip: &IpAddr, host: &nmap::Host, whitelist: &whitelist::Whitelist) -> AnalysisResult {
    let ports: Vec<PortAnalysisResult> = host.ports.ports.iter().map( |port| {
        // TODO Handle case where port is not found: Has it been scanned? -> extraports
        let wl_port = if let Some(wp) = whitelist.ports.iter().find(|x| x.id== port.portid) {
            wp
        } else {
            let par = PortAnalysisResult::Unknown(port.portid);
            println!("Result for host {}, port {} is {:?}",  ip, port.portid, par);
            return par;
        };
        let par = match wl_port {
            whitelist::Port { id: _, state: whitelist::PortState::Open }
                if port.state.state == nmap::PortStatus::Open => PortAnalysisResult::Pass(port.portid),
            whitelist::Port { id: _, state: whitelist::PortState::Closed }
                if port.state.state != nmap::PortStatus::Open => PortAnalysisResult::Pass(port.portid),
            _ => PortAnalysisResult::Fail(port.portid),
        };
        println!("Result for host {}, port {} is {:?}",  ip, port.portid, par);
        par
    }).collect();

    println!("Results for host {} is {:?}", ip, ports);

    let failed = ports.iter().filter(|x| match x {
        PortAnalysisResult::Pass(_) => false,
        _ => true,
    }).count();
    if failed > 0 {
        AnalysisResult::Fail
    } else {
        AnalysisResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nmap;
    use mapping;
    use whitelist;

    use spectral::prelude::*;

    #[test]
    fn run_to_scanned_hosts_by_ip_okay() {
        let run = nmap_data();

        let shbi: HashMap<_, _> = run_to_scanned_hosts_by_ip(&run);

        assert_eq!(shbi.len(), 2);
        let host1_ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(shbi.get(&host1_ip).is_some());
        let host3_ip: IpAddr = "192.168.0.3".parse().unwrap();
        assert!(shbi.get(&host3_ip).is_some());
    }

    #[test]
    fn whitelists_to_whitelist_by_name_okay() {
        let whitelists = whitelists_data();

        let wbn: HashMap<_, _> = whitelists_to_whitelist_by_name(&whitelists);

        assert_eq!(wbn.len(), 2);
        assert!(wbn.get("Group A").is_some());
        assert!(wbn.get("Group B").is_some());
    }


    #[test]
    fn whitelist_by_ip_okay() {
        let mapping = mapping_data();
        let whitelists = whitelists_data();

        let wbi: HashMap<_, _> = whitelist_by_ip(&mapping, &whitelists);

        assert_eq!(wbi.len(), 2);

        let host1_ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(wbi.get(&host1_ip).is_some());
        assert_eq!(wbi.get(&host1_ip).unwrap().name, "Group A");

        let host3_ip: IpAddr = "192.168.0.3".parse().unwrap();
        assert!(wbi.get(&host3_ip).is_some());
        assert_eq!(wbi.get(&host3_ip).unwrap().name, "Group B");
    }

    #[test]
    fn analyze_okay() {
        let nmap = nmap_data();
        let mapping = mapping_data();
        let whitelists = whitelists_data();

        let analyzer = Analyzer::new(&nmap, &mapping, &whitelists);
        let analysis_results = analyzer.analyze();

        assert_that!(&analysis_results).has_length(2);
        assert_that!(&analysis_results.get(0)).is_some().is_equal_to(&AnalysisResult::Fail);
        assert_that!(&analysis_results.get(1)).is_some().is_equal_to(&AnalysisResult::Pass);
    }

    fn nmap_data() -> nmap::Run {
        use nmap::*;

        let host1 = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0
            },
            address: Address {
                addr: "192.168.0.1".parse().unwrap(),
            },
            hostnames: HostNames {
                hostnames: vec![
                    HostName {
                        name: "192.168.0.1".to_owned(),
                        typ: HostNameType::User
                    }
                ]
            },
            ports: Ports {
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        portid: 25,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244
                        },
                        service: PortService {
                            name: "smtp".to_owned(),
                            method: "table".to_owned(),
                            conf: 3
                        }
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        portid: 80,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244
                        },
                        service: PortService {
                            name: "http".to_owned(),
                            method: "table".to_owned(),
                            conf: 3
                        }
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        portid: 443,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3
                        }
                    }
                ]
            }
        };

        let host3 = Host {
            starttime: 1531991145,
            endtime: 1531991170,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0
            },
            address: Address {
                addr: "192.168.0.3".parse().unwrap(),
            },
            hostnames: HostNames {
                hostnames: vec![
                    HostName {
                        name: "192.168.0.3".to_owned(),
                        typ: HostNameType::User
                    }
                ]
            },
            ports: Ports {
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        portid: 80,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "reset".to_owned(),
                            reason_ttl: 244
                        },
                        service: PortService {
                            name: "http".to_owned(),
                            method: "table".to_owned(),
                            conf: 3
                        }
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        portid: 443,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3
                        }
                    }
                ]
            }
        };

        let hosts = vec![host1, host3];

        Run {
            scanner: "nmap".to_owned(),
            args: "nmap -v -n -Pn -T4 -sS -oX nmap-3hosts-result.xml 192.168.0.1 192.168.0.2 192.168.0.3".to_owned(),
            start: 1531991145,
            hosts,
        }
    }

    fn mapping_data() -> mapping::Mapping {
        use mapping::*;

        vec![
            Host {
                id: "i-0".to_owned(),
                hostname: "ec2-192.168.0.1".to_owned(),
                ip: "192.168.0.1".parse().unwrap(),
                name: "Group A server".to_owned(),
                whitelist: "Group A".to_owned(),
            },
            Host {
                id: "i-0".to_owned(),
                hostname: "ec2-192.168.0.3".to_owned(),
                ip: "192.168.0.3".parse().unwrap(),
                name: "Group B server".to_owned(),
                whitelist: "Group B".to_owned(),
            },
        ]
    }

    fn whitelists_data() -> whitelist::Whitelists {
        use whitelist::*;

        Whitelists {
            whitelists: vec![
                Whitelist {
                    name: "Group A".to_owned(),
                    ports: vec![
                        Port {
                            id: 22,
                            state: PortState::Closed
                        },
                        Port {
                            id: 25,
                            state: PortState::Open
                        }
                    ]
                },
                Whitelist {
                    name: "Group B".to_owned(),
                    ports: vec![
                        Port {
                            id: 80,
                            state: PortState::Open
                        },
                        Port {
                            id: 443,
                            state: PortState::Open
                        }
                    ]
                }
            ]
        }
    }

}
