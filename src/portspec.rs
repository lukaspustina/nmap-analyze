use super::{from_str, FromFile};

use serde_yaml;
use std::str::FromStr;

error_chain! {
    errors {
        InvalidPortSpecsFile {
            description("invalid port specs file")
        }
        InvalidPortSpecs {
            description("invalid port specs")
        }
        InvalidPortState(invalid: String) {
            description("invalid port state")
            display("invalid port state: {}", invalid)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortSpecs {
    #[serde(rename = "portspecs")]
    pub port_specs: Vec<PortSpec>,
}

impl FromStr for PortSpecs {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        PortSpecs::from_bytes(s.as_bytes())
    }
}

impl PortSpecs {
    fn from_bytes(buffer: &[u8]) -> Result<Self> {
        serde_yaml::from_slice(buffer).chain_err(|| ErrorKind::InvalidPortSpecs)
    }
}

impl FromFile for PortSpecs {}

#[derive(Debug, Deserialize)]
pub struct PortSpec {
    pub name: String,
    pub ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
pub struct Port {
    pub id: u16,
    #[serde(deserialize_with = "from_str")]
    pub state: PortState,
}

#[derive(Debug)]
pub enum PortState {
    Closed,
    Open,
}

impl FromStr for PortState {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "closed" => Ok(PortState::Closed),
            "open" => Ok(PortState::Open),
            _ => Err(Error::from_kind(ErrorKind::InvalidPortState(s))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use spectral::prelude::*;

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

        let res = PortSpecs::from_str(s);
        println!("{:#?}", res);

        assert_that(&res).is_ok();
        let port_specs = res.unwrap();
        assert_that(&port_specs.port_specs).has_length(2);
    }
}
