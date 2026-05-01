use crate::{from_str, FromFile};

use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid port specs: {0}")]
    InvalidPortSpecs(#[from] serde_yaml_ng::Error),
    #[error("invalid port state: {0}")]
    InvalidPortState(String),
}

#[derive(Debug, Deserialize)]
pub struct PortSpecs {
    #[serde(rename = "portspecs")]
    pub port_specs: Vec<PortSpec>,
}

impl FromStr for PortSpecs {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_yaml_ng::from_slice(s.as_bytes())?)
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
    /// The Port is expected to be closed.
    Closed,
    /// The Port might be either open or closed.
    Maybe,
    /// The Port is expected to be open.
    Open,
}

impl FromStr for PortState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "closed" => Ok(PortState::Closed),
            "maybe" => Ok(PortState::Maybe),
            "open" => Ok(PortState::Open),
            _ => Err(Error::InvalidPortState(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_portspecs_okay() {
        let s = r##"---
portspecs:
  - name: Group A
    ports:
      - id: 22
        state: closed
      - id: 25
        state: maybe
  - name: Group B
    ports:
      - id: 80
        state: open
      - id: 443
        state: open
        "##;

        let port_specs = PortSpecs::from_str(s).expect("parse failed");
        assert_eq!(port_specs.port_specs.len(), 2);
    }
}
