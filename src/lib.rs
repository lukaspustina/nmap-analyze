extern crate clams;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_xml_rs;
extern crate serde_yaml;

#[cfg(test)]
#[macro_use]
extern crate spectral;

pub mod analyze;
pub mod mapping;
pub mod nmap;
pub mod portspec;

pub use analyze::{Analyzer, Analysis, AnalysisResult};
pub use mapping::Mapping;
pub use nmap::Run;
pub use portspec::PortSpecs;

use serde::de::{self, Deserialize, Deserializer};
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

error_chain! {
    errors {
        InvalidFileFormat {
            description("invalid file format")
        }
    }
}

pub trait FromFile {
    fn from_file<P: AsRef<Path>, E>(path: P) -> ::std::result::Result<Self, Error>
        where Self: Sized + FromStr<Err = E>, E: error_chain::ChainedError {

            let contents = Self::string_from_file(path)
            .chain_err(|| ErrorKind::InvalidFileFormat)?;

        Self::from_str(&contents)
            .chain_err(|| ErrorKind::InvalidFileFormat)
    }

    fn string_from_file<P: AsRef<Path>>(path: P) -> ::std::result::Result<String, ::std::io::Error> {
        let path: &Path = path.as_ref();

        let mut file = File::open(path)?;
        let mut contents = String::new();
        let _ = file.read_to_string(&mut contents)?;

        Ok(contents)
    }
}

pub trait SanityCheck {
    type Error;
    fn is_sane(&self) -> ::std::result::Result<(), Self::Error>;
}

fn from_str<'de, T, D>(deserializer: D) -> ::std::result::Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}

