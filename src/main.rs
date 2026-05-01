use anyhow::Context;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use log::{debug, error, info};
use nmap_analyze::output::{HumanOutput, JsonOutput, OutputConfig, OutputDetail, OutputFormat};
use nmap_analyze::*;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliOutputFormat {
    Human,
    Json,
    None,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Human => OutputFormat::Human,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::None => OutputFormat::None,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliOutputDetail {
    Fail,
    All,
}

impl From<CliOutputDetail> for OutputDetail {
    fn from(value: CliOutputDetail) -> Self {
        match value {
            CliOutputDetail::Fail => OutputDetail::Fail,
            CliOutputDetail::All => OutputDetail::All,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "nmap-analyze",
    version,
    about = "analyze nmap xml output and compares port states with specification"
)]
struct Args {
    /// Nmap XML file
    #[arg(short = 'n', long = "nmap")]
    nmap: PathBuf,
    /// Mapping file
    #[arg(short = 'm', long = "mapping")]
    mapping: PathBuf,
    /// Portspec file
    #[arg(short = 'p', long = "portspec")]
    portspec: PathBuf,
    /// Select output format
    #[arg(short = 'o', long = "output", value_enum, default_value_t = CliOutputFormat::Human)]
    output_format: CliOutputFormat,
    /// Select output detail level for human output
    #[arg(long = "output-detail", value_enum, default_value_t = CliOutputDetail::Fail)]
    output_detail: CliOutputDetail,
    /// Do not use colored output
    #[arg(long = "no-color")]
    no_color: bool,
    /// Silencium; use this for json output
    #[arg(short = 's', long = "silent")]
    silent: bool,
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbosity: u8,
}

fn main() -> ExitCode {
    let args = Args::parse();
    setup(env!("CARGO_PKG_NAME"), &args);
    debug!("args = {:#?}", args);

    let output_config = OutputConfig {
        detail: args.output_detail.into(),
        format: args.output_format.into(),
        color: !args.no_color,
    };

    match run(&args, &output_config) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            error!("error: {:#}", e);
            eprintln!("error: {:#}", e);
            ExitCode::from(1)
        }
    }
}

fn setup(name: &str, args: &Args) {
    colored::control::set_override(!args.no_color);

    let level = match args.verbosity {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    if !args.silent {
        eprintln!(
            "{} version={}, log level={:?}",
            name,
            env!("CARGO_PKG_VERSION"),
            level
        );
    }

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Error)
        .filter_module(name, level)
        .filter_module(env!("CARGO_PKG_NAME").replace('-', "_").as_str(), level)
        .target(env_logger::Target::Stderr)
        .try_init()
        .ok();
}

fn run(args: &Args, output_config: &OutputConfig) -> anyhow::Result<u8> {
    run_nmap_analyze(
        &args.nmap,
        &args.mapping,
        &args.portspec,
        output_config,
        args.silent,
    )
}

fn run_nmap_analyze<T: AsRef<Path>>(
    nmap_file: T,
    mapping_file: T,
    portspecs_file: T,
    output_config: &OutputConfig,
    silent: bool,
) -> anyhow::Result<u8> {
    info!("Loading port specification file");
    let portspecs =
        PortSpecs::from_file(portspecs_file.as_ref()).context("failed to load port specs file")?;
    info!("Loading mappings file");
    let mapping =
        Mapping::from_file(mapping_file.as_ref()).context("failed to load mapping file")?;
    info!("Loading nmap file");
    let nmap_run = Run::from_file(nmap_file.as_ref()).context("failed to load nmap file")?;
    info!("Checking nmap sanity");
    nmap_run
        .is_sane()
        .context("nmap file failed sanity check")?;

    info!("Analyzing");
    let analyzer_result = default_analysis(&nmap_run, &mapping, &portspecs);
    debug!("{:#?}", analyzer_result);

    info!("Outputting results"); // Don't bail just because there is an output problem.
    if let Err(x) = output(output_config, &analyzer_result) {
        error!("Output failed because {}", x);
    }

    info!("Summarizing");
    if !silent {
        println!(
            "Analyzer result summary: {}={}, {}={}, {}={}",
            "passed".green(),
            analyzer_result.pass,
            "failed".red(),
            analyzer_result.fail,
            "errored".red(),
            analyzer_result.error,
        );
    }

    let code = match analyzer_result {
        AnalyzerResult {
            fail: 0, error: 0, ..
        } => 0,
        AnalyzerResult {
            fail: x, error: 0, ..
        } if x > 0 => 11,
        AnalyzerResult { error: x, .. } if x > 0 => 12,
        AnalyzerResult { .. } => {
            error!("This not possible and just to satify the compiler");
            13
        }
    };
    Ok(code)
}

fn output(
    output_config: &OutputConfig,
    analyzer_result: &AnalyzerResult,
) -> Result<(), nmap_analyze::output::Error> {
    match output_config.format {
        OutputFormat::Human => analyzer_result.output_tty(output_config),
        OutputFormat::Json => {
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            JsonOutput::output(analyzer_result, output_config, &mut writer)
        }
        OutputFormat::None => Ok(()),
    }
}
