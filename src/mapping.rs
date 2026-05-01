use crate::FromFile;

use serde::{Deserialize, Deserializer};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid mappings: {0}")]
    InvalidMappings(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct Mapping {
    pub mappings: Vec<Host>,
}

impl FromStr for Mapping {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_slice(s.as_bytes())?)
    }
}

impl FromFile for Mapping {}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub id: Option<String>,
    pub hostname: Option<String>,
    #[serde(deserialize_with = "vec_ip_addr")]
    pub ips: Vec<IpAddr>,
    pub name: Option<String>,
    #[serde(rename = "portspec")]
    pub port_spec: String,
}

fn vec_ip_addr<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let v = Vec::<String>::deserialize(deserializer)?;
    v.into_iter()
        .map(|a| IpAddr::from_str(&a).map_err(Error::custom))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mapping_okay() {
        let s = r##"
{ "mappings":
    [
        {
            "hostname": "ec2-192.168.0.1",
            "id": "i-0",
            "ips": ["192.168.0.1"],
            "name": "Group A server",
            "portspec": "Group A"
        },
        {
            "hostname": "ec2-192.168.0.2",
            "id": "i-1",
            "ips": ["192.168.0.2"],
            "name": "Group B server",
            "portspec": "Group B"
        },
        {
            "hostname": "ec2-192.168.0.3",
            "id": "i-2",
            "ips": ["192.168.0.3", "192.168.0.4"],
            "name": "Group A server",
            "portspec": "Group A"
        }
    ]
}
        "##;

        let mapping = Mapping::from_str(s).expect("parse failed");
        assert_eq!(mapping.mappings.len(), 3);
    }
}
