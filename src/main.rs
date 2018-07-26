extern crate clams;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate nmap_analyze;
#[macro_use]
extern crate structopt;

use clams::prelude::*;
use nmap_analyze::{mapping, nmap, portspec};
use std::path::PathBuf;
use structopt::StructOpt;

error_chain!{
    links {
        Mapping(mapping::Error, mapping::ErrorKind);
        Nmap(nmap::Error, nmap::ErrorKind);
        Portspec(portspec::Error, portspec::ErrorKind);
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "nmap-analyze",
    about = "analyze nmap xml output and compares port states with specification",
    raw(setting = "structopt::clap::AppSettings::ColoredHelp")
)]
struct Args {
    /// Nmap XML file
    #[structopt(short = "n", long = "nmap", parse(from_os_str))]
    nmap: PathBuf,
    /// Mapping file
    #[structopt(short = "m", long = "mapping", parse(from_os_str))]
    mapping: PathBuf,
    /// Portspec file
    #[structopt(short = "p", long = "portspec", parse(from_os_str))]
    portspec: PathBuf,
    /// Select output format
    #[structopt(short = "o", long = "output", default_value = "human")]
    output: String,
    /// Do not use colored output
    #[structopt(long = "no-color")]
    no_color: bool,
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbosity: u64,
}

fn run() -> Result<i32> {
    let args = Args::from_args();
    clams::console::set_color(!args.no_color);
    let name = Args::clap().get_name().to_owned();

    let level: Level = args.verbosity.into();
    eprintln!("{} version={}, log level={:?}",
        &name,
        env!("CARGO_PKG_VERSION"),
        &level
    );

    let log_config = LogConfig::new(
      std::io::stderr(),
      false,
      Level(log::LevelFilter::Error),
      vec![
        ModLevel {
            module: name,
            level,
        },
      ],
      None,
    );

    init_logging(log_config)
      .expect("Failed to initialize logging");
    debug!("args = {:#?}", args);

    Ok(0)
}

quick_main!(run);

