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
pub struct PortSpecs {
    #[serde(rename = "portspecs")]
    pub port_specs: Vec<PortSpec>,
}

#[derive(Debug, Deserialize)]
pub struct PortSpec {
    pub name: String,
    pub ports: Vec<Port>
}

#[derive(Debug, Deserialize)]
pub struct Port {
    pub id: u16,
    #[serde(deserialize_with = "from_str")]
    pub state: PortState
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

#[cfg(test)]
mod tests {
    use super::*;

    use serde_yaml;

    #[test]
    fn parse_portspecs_okay() {
        let s = r##"---
portspecs:
  - name: Group A
    ports:
      - id: 22
        state: closed
      - id: 25
        state: open
  - name: Group B
    ports:
      - id: 80
        state: open
      - id: 443
        state: open
        "##;
        let port_specs: PortSpecs = serde_yaml::from_str(s).unwrap();
        println!("{:#?}", port_specs);
    }
}
