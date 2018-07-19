use super::from_str;

use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Fail)]
pub enum WhiltelistError {
    #[fail(display = "invalid port state: {}", invalid)]
    InvalidPortState {
        invalid: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct Whitelists {
    pub whitelists: Vec<Whitelist>,
}

#[derive(Debug, Deserialize)]
pub struct Whitelist {
    name: String,
    ports: Vec<Port>
}

#[derive(Debug, Deserialize)]
pub struct Port {
    id: u16,
    #[serde(deserialize_with = "from_str")]
    state: PortState
}

#[derive(Debug)]
pub enum PortState {
    Closed,
    Open,
}

impl FromStr for PortState {
    type Err = WhiltelistError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "closed" => Ok(PortState::Closed),
            "open" => Ok(PortState::Open),
            _ => Err(WhiltelistError::InvalidPortState{ invalid: s })
        }
    }
}

pub type Mapping = Vec<Host>;

#[derive(Debug, Deserialize)]
pub struct Host {
    id: String,
    hostname: String,
    #[serde(deserialize_with = "from_str")]
    ip: IpAddr,
    name: String,
    whitelist: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;
    use serde_yaml;

    #[test]
    fn parse_whitelists_okay() {
        let s = r##"---
whitelists:
  - name: Group A
    ports:
      - id: 22
        state: closed
      - id: 25
        state: open
  - name: Group B
    ports:
      - id: 22
        state: open
        "##;
        let whitelists: Whitelists = serde_yaml::from_str(s).unwrap();
        println!("{:#?}", whitelists);
    }


    #[test]
    fn parse_mapping_okay() {
        let s = r##"
[
  {
    "hostname": "ec2-192.168.0.1",
    "id": "i-0",
    "ip": "192.168.0.1",
    "name": "Group A server",
    "whitelist": "Group A"
  },
  {
    "hostname": "ec2-192.168.0.2",
    "id": "i-1",
    "ip": "192.168.0.2",
    "name": "Group B server",
    "whitelist": "Group B"
  },
  {
    "hostname": "ec2-192.168.0.3",
    "id": "i-2",
    "ip": "192.168.0.3",
    "name": "Group A server",
    "whitelist": "Group A"
  }
]
        "##;
        let mapping: Mapping = serde_json::from_str(s).unwrap();
        println!("{:#?}", mapping);
    }
}
