use mapping::Mapping;
use nmap::Run;
use whitelist::Whitelists;

#[derive(Debug, PartialEq)]
pub enum Analysis {
    Pass,
    Fail,
    Error,
}

pub struct Analyzer {
    nmap_run: Run,
    mapping: Mapping,
    whitelists: Whitelists,
}

impl Analyzer {
    pub fn new(nmap_run: Run, mapping: Mapping, whitelists: Whitelists) -> Analyzer {
        Analyzer{ nmap_run, mapping, whitelists }
    }

    pub fn analyze(&self) -> Analysis {
        Analysis::Error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nmap;
    use mapping;
    use whitelist;

    #[test]
    fn analyze_okay() {
        let nmap = nmap_data();
        let mapping = mapping_data();
        let whitelists = whitelists_data();

        let analyzer = Analyzer::new(nmap, mapping, whitelists);
        let result = analyzer.analyze();

        assert_eq!(result, Analysis::Pass);
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
                            id: 22,
                            state: PortState::Open
                        }
                    ]
                }
            ]
        }
    }

}
