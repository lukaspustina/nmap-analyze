#[macro_use]
extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_xml_rs;
extern crate serde_yaml;

#[cfg(test)]
#[macro_use]
extern crate spectral;

use failure::Error;
use serde::de::{self, Deserialize, Deserializer};
use std::fmt::Display;
use std::str::FromStr;

fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}

pub trait SanityCheck {
    fn is_sane(&self) -> Result<(), Error>;
}

pub mod analyze;
pub mod mapping;
pub mod nmap;
pub mod portspec;

pub use nmap::Run;
