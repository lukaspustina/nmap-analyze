extern crate clams;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate nmap_analyze;
#[macro_use]
extern crate structopt;

use clams::prelude::*;
use nmap_analyze::*;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

error_chain!{
    errors {
        InvalidFile {
            description("Failed to load invalid file")
        }
    }
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

    let name = "nmap_analyze".to_owned();
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

    run_nmap_analyze(&args.nmap, &args.mapping, &args.portspec)
}

fn run_nmap_analyze<T: AsRef<Path>>(nmap_file: T, mapping_file: T, portspecs_file: T) -> Result<i32> {
    info!("Loading port specification file");
    let portspecs = PortSpecs::from_file(portspecs_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;
    info!("Loading mappings file");
    let mapping = Mapping::from_file(mapping_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;
    info!("Loading nmap file");
    let nmap_run = Run::from_file(nmap_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;

    let analyzer_result = default_analysis(&nmap_run, &mapping, &portspecs);
    info!("Analysis finished.");
    println!("Analyzer result summary: pass={}, failed={}, errors={}",
          analyzer_result.pass,
          analyzer_result.fail,
          analyzer_result.error,
    );
    debug!("{:#?}", analyzer_result);

    match analyzer_result {
        AnalyzerResult{ fail: 0, error: 0, .. } => {
            Ok(0)
        },
        AnalyzerResult{ fail: x, error: 0, .. } if x > 0 => {
            Ok(1)
        },
        AnalyzerResult{ error: x, .. } if x > 0 => {
            Ok(10)
        },
        AnalyzerResult{ .. } => {
            error!("This not possible and just to satify the compiler");
            Ok(100)
        },
    }
}

#[derive(Debug)]
struct AnalyzerResult<'a> {
    pass: usize,
    fail: usize,
    error: usize,
    analysis_results: Vec<Analysis<'a>>
}

fn default_analysis<'a>(nmap_run: &'a Run, mapping: &'a Mapping, portspecs: &'a PortSpecs) -> AnalyzerResult<'a> {
    let analyzer = Analyzer::new(&nmap_run, &mapping, &portspecs);
    let analysis_results = analyzer.analyze();

    let mut pass = 0;
    let mut fail = 0;
    let mut error = 0;
    for ar in &analysis_results {
        match ar.result {
            AnalysisResult::Pass => {pass = pass + 1;},
            AnalysisResult::Fail => {fail = fail + 1;},
            AnalysisResult::Error{ reason: _ } => {error = error + 1;},
        }
    }
    let result = AnalyzerResult {
        pass,
        fail,
        error,
        analysis_results,
    };

    result
}

quick_main!(run);

