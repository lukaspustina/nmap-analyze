use mapping::Mapping;
use nmap::{self, Run};
use portspec::{self, PortSpecs};

use std::collections::{BTreeMap, HashSet};
use std::iter::FromIterator;
use std::net::IpAddr;

static IMPLICIT_CLOSED_PORTSPEC: &portspec::Port = &portspec::Port {
    id: 0,
    state: portspec::PortState::Closed,
};

#[derive(Debug, Serialize)]
pub struct Analysis<'a> {
    ip: &'a IpAddr,
    result: AnalysisResult,
    port_results: Vec<PortAnalysisResult>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum AnalysisResult {
    Pass,
    Fail,
    Error{ reason: String },
}

#[derive(Debug, PartialEq, Serialize)]
pub enum PortAnalysisResult {
    Pass(u16),
    Fail(u16, PortAnalysisReason),
    NotScanned(u16),
    Unknown(u16),
}

#[derive(Debug, PartialEq, Serialize)]
pub enum PortAnalysisReason {
    OpenButClosed, // Should have been open, but was found to be closed
    ClosedButOpen, // Should have been cloed, but was found to be open
    Unknown,
}

pub struct Analyzer<'a> {
    scanned_host_by_ip: BTreeMap<&'a IpAddr, &'a nmap::Host>,
    portspec_by_ip: BTreeMap<&'a IpAddr, &'a portspec::PortSpec>,
}

impl<'a> Analyzer<'a> {
    pub fn new<'b>(
        nmap_run: &'b Run,
        mapping: &'b Mapping,
        portspecs: &'b PortSpecs,
    ) -> Analyzer<'b> {
        let scanned_host_by_ip = run_to_scanned_hosts_by_ip(&nmap_run);
        let portspec_by_ip = portspec_by_ip(&mapping, &portspecs);

        Analyzer {
            scanned_host_by_ip,
            portspec_by_ip,
        }
    }

    pub fn analyze(&self) -> Vec<Analysis> {
        self.scanned_host_by_ip
            .iter()
            .map(|(ip, host)| {
                match self.portspec_by_ip.get(ip) {
                    Some(wl) => analyze_host(ip, host, wl),
                    None => Analysis {
                        ip,
                        result: AnalysisResult::Error{reason: "No port spec found for this IP address".to_owned()},
                        port_results: Vec::new(),
                    }
                }
            })
            .collect()
    }
}

fn run_to_scanned_hosts_by_ip(nmap_run: &Run) -> BTreeMap<&IpAddr, &nmap::Host> {
    let mut shbi = BTreeMap::new();
    for host in &nmap_run.hosts {
        shbi.insert(&host.address.addr, host);
    }

    shbi
}

fn portspec_by_ip<'a>(
    mapping: &'a Mapping,
    portspec: &'a PortSpecs,
) -> BTreeMap<&'a IpAddr, &'a portspec::PortSpec> {
    let pss = portspecs_to_portspec_by_name(portspec);
    let mut psbi= BTreeMap::new();

    for m in mapping {
        let key: &str = &m.port_spec;
        if let Some(ps) = pss.get(key) {
            psbi.insert(&m.ip, *ps);
        }
    }

    psbi
}

fn portspecs_to_portspec_by_name(portspecs: &PortSpecs) -> BTreeMap<&str, &portspec::PortSpec> {
    let mut wbn = BTreeMap::new();
    for wl in &portspecs.port_specs {
        wbn.insert(wl.name.as_ref(), wl);
    }

    wbn
}

/// This methods analyses the nmap port scanning results for a specific host. It uses the portspec of the group the hosts is mapped to.
///
/// First, we must check that the explicitly specified port specs are met, i.e., if the specified ports
/// are closed or open respectively. This step may have three different results for each specified
/// port: 1. The port state is as expected, 2. the port state it _not_ as expected, and 3. the port
/// has not be scanned.
///
/// Second, we must check that all other scanned ports are closed which is implicitly specified if
/// not explicitly required to be in state open.
///
/// The analysis result is determined like this:
/// - If all ports meet the explicit and implicit expectations: Pass
/// - If an explicitly specified port has not been scaned: Fail
/// - If one or more ports do not meet the expectations: Fail
fn analyze_host<'a>(
    ip: &'a IpAddr,
    host: &nmap::Host,
    portspec: &portspec::PortSpec,
) -> Analysis<'a> {
    let mut unscanned_ps_ports: HashSet<u16> =
        HashSet::from_iter(portspec.ports.iter().map(|x| x.id));

    let mut ports: Vec<PortAnalysisResult> = host
        .ports
        .ports
        .iter()
        .map(|port| {
            // Remove the current port from the unscanned, explicitly specified ports.
            let _ = unscanned_ps_ports.remove(&port.id);

            // if port is not explicitly specified then we implicitly set the expected state to closed
            let ps_port = if let Some(p) = portspec.ports.iter().find(|x| x.id == port.id) {
                p
            } else {
                &IMPLICIT_CLOSED_PORTSPEC
            };
            let par = match ps_port {
                portspec::Port {
                    state: portspec::PortState::Open,
                    ..
                }
                    if port.state.state == nmap::PortStatus::Open =>
                {
                    PortAnalysisResult::Pass(port.id)
                }
                portspec::Port {
                    state: portspec::PortState::Open,
                    ..
                } => PortAnalysisResult::Fail(port.id, PortAnalysisReason::OpenButClosed),
                portspec::Port {
                    state: portspec::PortState::Closed,
                    ..
                }
                    if port.state.state != nmap::PortStatus::Open =>
                {
                    PortAnalysisResult::Pass(port.id)
                }
                portspec::Port {
                    state: portspec::PortState::Closed,
                    ..
                } => PortAnalysisResult::Fail(port.id, PortAnalysisReason::ClosedButOpen),
            };
            trace!("Result for host {}, port {} is {:?}", ip, port.id, par);
            par
        })
        .collect();

    // Add all (remaning) unscanned, explicitly specified ports to the result as "NotScanned"
    ports.extend(
        unscanned_ps_ports
            .iter()
            .map(|x| PortAnalysisResult::NotScanned(*x)),
    );

    debug!("Results for host {} is {:?}", ip, ports);

    let failed = ports
        .iter()
        .filter(|x| match x {
            PortAnalysisResult::Pass(_) => false,
            _ => true,
        })
        .count();
    let result = if failed > 0 {
        AnalysisResult::Fail
    } else {
        AnalysisResult::Pass
    };

    Analysis {
        ip,
        result,
        port_results: ports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mapping;
    use nmap;
    use portspec;

    use spectral::prelude::*;

    #[test]
    fn analyzer_no_mapping_for_ip() {
        let portspecs = portspec::PortSpecs {
            port_specs: vec![
                portspec::PortSpec {
                    name: "Unused Group".to_owned(),
                    ports: vec![
                        portspec::Port {
                            id: 22,
                            state: portspec::PortState::Closed,
                        },
                        portspec::Port {
                            id: 25,
                            state: portspec::PortState::Open,
                        },
                    ],
                },
            ]
        };
        let nmap = nmap_data();
        let mapping = mapping_data();

        let analyzer = Analyzer::new(&nmap, &mapping, &portspecs);
        let analysis = analyzer.analyze();
        println!("Analysis: {:?}", analysis);

        assert_that(&analysis).has_length(2);
        let res0 = &analysis[0];
        assert_that!(&res0.result).is_equal_to(AnalysisResult::Error{reason: "No port spec found for this IP address".to_owned()});
        let res1 = &analysis[1];
        assert_that!(&res1.result).is_equal_to(AnalysisResult::Error{reason: "No port spec found for this IP address".to_owned()});
    }

    #[test]
    fn analyze_host_explicit_and_implicit_ports_okay() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap(); // Safe
        let portspec = portspec::PortSpec {
            name: "Group A".to_owned(),
            ports: vec![
                portspec::Port {
                    id: 22,
                    state: portspec::PortState::Closed,
                },
                portspec::Port {
                    id: 25,
                    state: portspec::PortState::Open,
                },
            ],
        };
        use nmap::*;
        let host = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address { addr: ip.clone() },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: format!("{}", ip),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 22,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "ssh".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 25,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "smtp".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
        };

        let analysis = analyze_host(&ip, &host, &portspec);
        println!("Analysis: {:?}", analysis);

        assert_that!(&analysis.result).is_equal_to(AnalysisResult::Pass);
    }

    #[test]
    fn analyze_host_explicit_port_fail() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap(); // Safe
        let portspec = portspec::PortSpec {
            name: "Group A".to_owned(),
            ports: vec![
                portspec::Port {
                    id: 22,
                    state: portspec::PortState::Closed,
                },
                portspec::Port {
                    id: 25,
                    state: portspec::PortState::Open,
                },
            ],
        };
        use nmap::*;
        let host = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address { addr: ip.clone() },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: format!("{}", ip),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 22,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "ssh".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 25,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "smtp".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
        };

        let analysis = analyze_host(&ip, &host, &portspec);
        println!("Analysis: {:?}", analysis);

        assert_that!(&analysis.result).is_equal_to(AnalysisResult::Fail);
    }

    #[test]
    fn analyze_host_explicit_port_not_scanned() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap(); // Safe
        let portspec = portspec::PortSpec {
            name: "Group A".to_owned(),
            ports: vec![
                portspec::Port {
                    id: 22,
                    state: portspec::PortState::Closed,
                },
                portspec::Port {
                    id: 25,
                    state: portspec::PortState::Open,
                },
            ],
        };
        use nmap::*;
        let host = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address { addr: ip.clone() },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: format!("{}", ip),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 22,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "ssh".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
        };

        let analysis = analyze_host(&ip, &host, &portspec);
        println!("Analysis: {:?}", analysis);

        asserting("Scan fails because an explicit port has not been scanned")
            .that(&analysis.result)
            .is_equal_to(AnalysisResult::Fail);

        let ports = &analysis.port_results;
        let unscanned: Vec<_> = ports
            .iter()
            .filter(|x| *x == &PortAnalysisResult::NotScanned(25u16))
            .collect();
        asserting("Port 25 has not been scanned")
            .that(&unscanned)
            .has_length(1);
    }

    #[test]
    fn analyze_host_implicit_port_open() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap(); // Safe
        let portspec = portspec::PortSpec {
            name: "Group A".to_owned(),
            ports: vec![
                portspec::Port {
                    id: 22,
                    state: portspec::PortState::Closed,
                },
                portspec::Port {
                    id: 25,
                    state: portspec::PortState::Open,
                },
            ],
        };
        use nmap::*;
        let host = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address { addr: ip.clone() },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: format!("{}", ip),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 22,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "ssh".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 25,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "smtp".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
        };

        let analysis = analyze_host(&ip, &host, &portspec);
        println!("Analysis: {:?}", analysis);

        asserting("Scan fails because an implicit port is open")
            .that(&analysis.result)
            .is_equal_to(AnalysisResult::Fail);

        let ports = &analysis.port_results;
        let unscanned: Vec<_> = ports
            .iter()
            .filter(|x| *x == &PortAnalysisResult::Fail(443u16, PortAnalysisReason::ClosedButOpen))
            .collect();
        asserting("Port 443 is open").that(&unscanned).has_length(1);
    }

    #[test]
    fn run_to_scanned_hosts_by_ip_okay() {
        let run = nmap_data();

        let shbi: BTreeMap<_, _> = run_to_scanned_hosts_by_ip(&run);

        assert_eq!(shbi.len(), 2);
        let host1_ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(shbi.get(&host1_ip).is_some());
        let host3_ip: IpAddr = "192.168.0.3".parse().unwrap();
        assert!(shbi.get(&host3_ip).is_some());
    }

    #[test]
    fn portspecs_to_portspec_by_name_okay() {
        let portspecs = portspecs_data();

        let wbn: BTreeMap<_, _> = portspecs_to_portspec_by_name(&portspecs);

        assert_eq!(wbn.len(), 2);
        assert!(wbn.get("Group A").is_some());
        assert!(wbn.get("Group B").is_some());
    }

    #[test]
    fn portspec_by_ip_okay() {
        let mapping = mapping_data();
        let portspecs = portspecs_data();

        let wbi: BTreeMap<_, _> = portspec_by_ip(&mapping, &portspecs);

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
        let portspecs = portspecs_data();

        let analyzer = Analyzer::new(&nmap, &mapping, &portspecs);
        let analysis_results = analyzer.analyze();

        assert_that!(&analysis_results).has_length(2);
        let res0 = analysis_results.get(0);
        assert_that!(&res0).is_some();
        assert_that!(&res0.unwrap().result).is_equal_to(AnalysisResult::Fail);
        let res1 = analysis_results.get(1);
        assert_that!(&res1).is_some();
        assert_that!(&res1.unwrap().result).is_equal_to(AnalysisResult::Pass);
    }

    fn nmap_data() -> nmap::Run {
        use nmap::*;

        let host1 = Host {
            starttime: 1531991145,
            endtime: 1531991167,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address {
                addr: "192.168.0.1".parse().unwrap(),
            },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: "192.168.0.1".to_owned(),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 25,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "smtp".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 80,
                        state: PortState {
                            state: PortStatus::Closed,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "http".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
        };

        let host3 = Host {
            starttime: 1531991145,
            endtime: 1531991170,
            status: HostStatus {
                state: HostState::Up,
                reason: "user-set".to_owned(),
                reason_ttl: 0,
            },
            address: Address {
                addr: "192.168.0.3".parse().unwrap(),
            },
            hostnames: HostNames {
                hostnames: vec![HostName {
                    name: "192.168.0.3".to_owned(),
                    typ: HostNameType::User,
                }],
            },
            ports: Ports {
                extra_ports: None,
                ports: vec![
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 80,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "reset".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "http".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                    Port {
                        protocol: "tcp".to_owned(),
                        id: 443,
                        state: PortState {
                            state: PortStatus::Open,
                            reason: "syn-ack".to_owned(),
                            reason_ttl: 244,
                        },
                        service: PortService {
                            name: "https".to_owned(),
                            method: "table".to_owned(),
                            conf: 3,
                        },
                    },
                ],
            },
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
                port_spec: "Group A".to_owned(),
            },
            Host {
                id: "i-0".to_owned(),
                hostname: "ec2-192.168.0.3".to_owned(),
                ip: "192.168.0.3".parse().unwrap(),
                name: "Group B server".to_owned(),
                port_spec: "Group B".to_owned(),
            },
        ]
    }

    fn portspecs_data() -> portspec::PortSpecs {
        use portspec::*;

        PortSpecs {
            port_specs: vec![
                PortSpec {
                    name: "Group A".to_owned(),
                    ports: vec![
                        Port {
                            id: 22,
                            state: PortState::Closed,
                        },
                        Port {
                            id: 25,
                            state: PortState::Open,
                        },
                    ],
                },
                PortSpec {
                    name: "Group B".to_owned(),
                    ports: vec![
                        Port {
                            id: 80,
                            state: PortState::Open,
                        },
                        Port {
                            id: 443,
                            state: PortState::Open,
                        },
                    ],
                },
            ],
        }
    }

}
