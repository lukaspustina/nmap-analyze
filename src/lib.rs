pub mod analyze;
pub mod mapping;
pub mod nmap;
pub mod output;
pub mod portspec;

pub use crate::analyze::{
    default_analysis, Analyzer, AnalyzerResult, HostAnalysisResult, HostAnalysisSummary,
};
pub use crate::mapping::Mapping;
pub use crate::nmap::Run;
pub use crate::portspec::PortSpecs;

use serde::de::{self, Deserialize, Deserializer};
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum FromFileError {
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid file format: {0}")]
    Parse(#[source] anyhow::Error),
}

pub trait FromFile: Sized + FromStr
where
    <Self as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, FromFileError> {
        let contents = fs::read_to_string(path.as_ref())?;
        Self::from_str(&contents).map_err(|e| FromFileError::Parse(anyhow::Error::new(e)))
    }
}

pub trait SanityCheck {
    type Error;
    fn is_sane(&self) -> std::result::Result<(), Self::Error>;
}

pub(crate) fn from_str<'de, T, D>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}
