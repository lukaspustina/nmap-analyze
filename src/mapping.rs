use super::FromFile;

use serde::{Deserialize, Deserializer};
use serde_json;
use std::net::IpAddr;
use std::str::FromStr;

error_chain! {
    errors {
        InvalidMappingFile {
            description("Invalid mappings file")
        }
        InvalidMappings {
            description("Invalid mappings")
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Mapping {
    pub mappings: Vec<Host>,
}

impl FromStr for Mapping {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        Mapping::from_bytes(s.as_bytes())
    }
}

impl Mapping {
    fn from_bytes(buffer: &[u8]) -> Result<Self> {
        serde_json::from_slice(buffer).chain_err(|| ErrorKind::InvalidMappings)
    }
}

impl FromFile for Mapping {}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    #[serde(deserialize_with = "vec_ip_addr")]
    pub ips: Vec<IpAddr>,
    pub name: String,
    #[serde(rename = "portspec")]
    pub port_spec: String,
}

fn vec_ip_addr<'de, D>(deserializer: D) -> ::std::result::Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let v = Vec::deserialize(deserializer)?;
    let res: ::std::result::Result<Vec<IpAddr>, _> = v
        .into_iter()
        .map(|a: &str| IpAddr::from_str(a).map_err(Error::custom))
        .collect();

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use spectral::prelude::*;

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

        let res = Mapping::from_str(s);
        println!("{:#?}", res);

        assert_that(&res).is_ok();
        let mapping = res.unwrap();
        assert_that(&mapping.mappings).has_length(3);
    }
}
