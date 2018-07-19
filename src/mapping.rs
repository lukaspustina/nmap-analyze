use super::from_str;

use std::net::IpAddr;
use std::str::FromStr;

pub type Mapping = Vec<Host>;

#[derive(Debug, Deserialize)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    #[serde(deserialize_with = "from_str")]
    pub ip: IpAddr,
    pub name: String,
    pub whitelist: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

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
