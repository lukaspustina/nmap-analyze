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
use nmap_analyze::output::{OutputConfig, OutputDetail, OutputFormat};
use std::path::{Path, PathBuf};
use structopt::StructOpt;

error_chain!{
    errors {
        InvalidFile {
            description("Failed to load invalid file")
        }
    }
    links {
        Output(output::Error, output::ErrorKind);
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
    #[structopt(short = "o", long = "output", default_value = "human", raw(possible_values = r#"&["human", "json", "none"]"#))]
    output_format: OutputFormat,
    /// Select output detail level for human output
    #[structopt(long = "output-detail", default_value = "fail", raw(possible_values = r#"&["fail", "all"]"#))]
    output_detail: OutputDetail,
    /// Do not use colored output
    #[structopt(long = "no-color")]
    no_color: bool,
    /// Silencium; use this for json output
    #[structopt(short = "s", long = "silent")]
    silent: bool,
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbosity: u64,
}

fn run() -> Result<i32> {
    let args = Args::from_args();
    setup("nmap_analyze", &args);
    debug!("args = {:#?}", args);

    let output_config = OutputConfig {
        detail: args.output_detail,
        format: args.output_format,
        color: !args.no_color,
    };

    run_nmap_analyze(&args.nmap, &args.mapping, &args.portspec, &output_config, args.silent)
}

fn setup(name: &str, args: &Args) {
    clams::console::set_color(!args.no_color);

    let level: Level = args.verbosity.into();
    if !args.silent {
        eprintln!("{} version={}, log level={:?}",
            name,
            env!("CARGO_PKG_VERSION"),
            &level
        );
    }

    let log_config = LogConfig::new(
      std::io::stderr(),
      false,
      Level(log::LevelFilter::Error),
      vec![
        ModLevel {
            module: name.to_owned(),
            level,
        },
      ],
      None,
    );

    init_logging(log_config)
      .expect("Failed to initialize logging");
}

fn run_nmap_analyze<T: AsRef<Path>>(nmap_file: T, mapping_file: T, portspecs_file: T, output_config: &OutputConfig, silent: bool) -> Result<i32> {
    info!("Loading port specification file");
    let portspecs = PortSpecs::from_file(portspecs_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;
    info!("Loading mappings file");
    let mapping = Mapping::from_file(mapping_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;
    info!("Loading nmap file");
    let nmap_run = Run::from_file(nmap_file.as_ref())
        .chain_err(|| ErrorKind::InvalidFile)?;
    info!("Checking nmap sanity");
    let _ = nmap_run.is_sane()
        .chain_err(|| ErrorKind::InvalidFile)?;

    info!("Analyzing");
    let analyzer_result = default_analysis(&nmap_run, &mapping, &portspecs);
    debug!("{:#?}", analyzer_result);

    info!("Outputting results"); // Don't bail just because there is an output problem.
    if let Err(x) = output(output_config, &analyzer_result) {
        error!("Output failed because {}", x);
    }

    info!("Summarizing");
    if !silent {
        println!("Analyzer result summary: {}={}, {}={}, {}={}",
            "passed".green(),
            analyzer_result.pass,
            "failed".red(),
            analyzer_result.fail,
            "errored".red(),
            analyzer_result.error,
        );
    }

    match analyzer_result {
        AnalyzerResult{ fail: 0, error: 0, .. } => {
            Ok(0)
        },
        AnalyzerResult{ fail: x, error: 0, .. } if x > 0 => {
            Ok(11)
        },
        AnalyzerResult{ error: x, .. } if x > 0 => {
            Ok(12)
        },
        AnalyzerResult{ .. } => {
            error!("This not possible and just to satify the compiler");
            Ok(13)
        },
    }
}

fn output(output_config: &OutputConfig, analyzer_result: &AnalyzerResult) -> Result<()> {
    match output_config.format {
        OutputFormat::Human => {
            use nmap_analyze::output::HumanOutput;
            analyzer_result.output_tty(output_config)
        },
        OutputFormat::Json => {
            use nmap_analyze::output::JsonOutput;
            let stdout = ::std::io::stdout();
            let mut writer = stdout.lock();
            analyzer_result.output(output_config, &mut writer)
        },
        OutputFormat::None => Ok(()),
    }.map_err(|e| e.into())
}

quick_main!(run);

