use analyze::{HostAnalysisSummary, AnalyzerResult, PortAnalysisReason, PortAnalysisResult};

use prettytable::cell::Cell;
use prettytable::row::Row;
use prettytable::{color, format, Attr, Table};
use serde_json;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;

error_chain!{
    errors {
        InvalidOutputFormat(reason: String) {
            description("invalid output format selected")
            display("invalid output format '{}' selected", reason)
        }
        InvalidOutputDetail(reason: String) {
            description("invalid output detail selected")
            display("Invalid output detail '{}' selected", reason)
        }
        OutputFailed {
            description("output failed")
        }
    }
}

#[derive(Debug)]
pub enum OutputFormat {
    Human,
    Json,
    None,
}

impl FromStr for OutputFormat {
    type Err = Error;
    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "human" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            "none" => Ok(OutputFormat::None),
            _ => Err(ErrorKind::InvalidOutputFormat(s.to_string()).into()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum OutputDetail {
    Fail,
    All,
}

impl FromStr for OutputDetail {
    type Err = Error;
    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "fail" => Ok(OutputDetail::Fail),
            "all" => Ok(OutputDetail::All),
            _ => Err(ErrorKind::InvalidOutputDetail(s.to_string()).into()),
        }
    }
}

#[derive(Debug)]
pub struct OutputConfig {
    pub detail: OutputDetail,
    pub format: OutputFormat,
    pub color: bool,
}

pub trait JsonOutput {
    fn output<T: Write>(&self, output_config: &OutputConfig, writer: &mut T) -> Result<()>;
}

pub trait HumanOutput {
    fn output<T: Write>(&self, output_config: &OutputConfig, writer: &mut T) -> Result<()>;
    fn output_tty(&self, output_config: &OutputConfig) -> Result<()>;
}

impl<'a> JsonOutput for AnalyzerResult<'a> {
    fn output<T: Write>(&self, _: &OutputConfig, writer: &mut T) -> Result<()> {
        let json_str = serde_json::to_string(self).chain_err(|| ErrorKind::OutputFailed)?;
        writer
            .write(json_str.as_bytes())
            .chain_err(|| ErrorKind::OutputFailed)?;

        Ok(())
    }
}

impl<'a> HumanOutput for AnalyzerResult<'a> {
    fn output<T: Write>(&self, output_config: &OutputConfig, writer: &mut T) -> Result<()> {
        self.build_table(output_config)
            .print(writer)
            .chain_err(|| ErrorKind::OutputFailed)
    }

    fn output_tty(&self, output_config: &OutputConfig) -> Result<()> {
        if output_config.color {
            self.build_table(output_config).printstd();
            Ok(())
        } else {
            let stdout = ::std::io::stdout();
            let mut writer = stdout.lock();
            self.build_table(output_config)
                .print(&mut writer)
                .chain_err(|| ErrorKind::OutputFailed)
        }
    }
}

impl<'a> AnalyzerResult<'a> {
    fn build_table(&self, output_config: &OutputConfig) -> Table {
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        table.set_titles(Row::new(vec![
            Cell::new("Host"),
            Cell::new("Portspec"),
            Cell::new("Result"),
            Cell::new("Port"),
            Cell::new("Port Result"),
            Cell::new("Failue Reason"),
        ]));

        for a in &self.host_analysis_results {
            if output_config.detail == OutputDetail::Fail && a.summary == HostAnalysisSummary::Pass {
                continue;
            }
            let row = Row::new(vec![
                Cell::new(ip_addr_to_string(a.ip).as_ref()),
                Cell::new(a.portspec_name.unwrap_or("")),
                analysis_result_to_cell(&a.summary),
                Cell::new(""),
                Cell::new(""),
                match a.summary {
                    HostAnalysisSummary::Error { ref reason } => Cell::new(reason),
                    _ => Cell::new(""),
                },
            ]);
            table.add_row(row);

            for p in &a.port_results {
                if let PortAnalysisResult::Pass(_) = p {
                    if output_config.detail == OutputDetail::Fail {
                        continue;
                    }
                }
                let row = Row::new(vec![
                    Cell::new(""),
                    Cell::new(""),
                    Cell::new(""),
                    Cell::new(port_analysis_result_to_port_string(&p).as_ref()),
                    port_analysis_result_to_port_result_cell(&p),
                    Cell::new(port_analysis_result_to_port_result_reason(&p).as_ref()),
                ]);
                table.add_row(row);
            }
        }

        table
    }
}

fn ip_addr_to_string(ip_addr: &IpAddr) -> String {
    format!("{}", ip_addr)
}

fn analysis_result_to_cell(result: &HostAnalysisSummary) -> Cell {
    match result {
        HostAnalysisSummary::Pass => Cell::new("Pass").with_style(Attr::ForegroundColor(color::GREEN)),
        HostAnalysisSummary::Fail => Cell::new("Fail").with_style(Attr::ForegroundColor(color::RED)),
        HostAnalysisSummary::Error { .. } => {
            Cell::new("Error").with_style(Attr::ForegroundColor(color::RED))
        }
    }
}

fn port_analysis_result_to_port_string(result: &PortAnalysisResult) -> String {
    let port = match result {
        PortAnalysisResult::Pass(x) => x,
        PortAnalysisResult::Fail(x, _) => x,
        PortAnalysisResult::NotScanned(x) => x,
        PortAnalysisResult::Unknown(x) => x,
    };
    format!("{}", port)
}

fn port_analysis_result_to_port_result_cell(result: &PortAnalysisResult) -> Cell {
    match result {
        PortAnalysisResult::Pass(_) => {
            Cell::new("passed").with_style(Attr::ForegroundColor(color::GREEN))
        }
        PortAnalysisResult::Fail(_, _) => {
            Cell::new("failed").with_style(Attr::ForegroundColor(color::RED))
        }
        PortAnalysisResult::NotScanned(_) => {
            Cell::new("not scanned").with_style(Attr::ForegroundColor(color::YELLOW))
        }
        PortAnalysisResult::Unknown(_) => {
            Cell::new("unknown").with_style(Attr::ForegroundColor(color::RED))
        }
    }
}

fn port_analysis_result_to_port_result_reason(result: &PortAnalysisResult) -> String {
    match result {
        PortAnalysisResult::Pass(_) => "",
        PortAnalysisResult::Fail(_, PortAnalysisReason::OpenButClosed) => {
            "expected Open, found Closed"
        }
        PortAnalysisResult::Fail(_, PortAnalysisReason::ClosedButOpen) => {
            "expected Closed, found Open"
        }
        PortAnalysisResult::Fail(_, PortAnalysisReason::Unknown) => "unknown",
        PortAnalysisResult::NotScanned(_) => "",
        PortAnalysisResult::Unknown(_) => "",
    }.to_owned()
}
