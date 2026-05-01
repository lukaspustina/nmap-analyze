use nmap_analyze::output::{HumanOutput, OutputConfig, OutputDetail, OutputFormat};
use nmap_analyze::*;

fn main() {
    let expected_output = r##"
+-------------+----------+--------+------+-------------+-----------------------------+
| Host        | Portspec | Result | Port | Port Result | Failure Reason              |
+-------------+----------+--------+------+-------------+-----------------------------+
| 192.168.0.1 | Group A  | Fail   |      |             |                             |
|             |          |        | 22   | failed      | expected Closed, found Open |
|             |          |        | 80   | failed      | expected Closed, found Open |
|             |          |        | 81   | failed      | expected Open, found Closed |
|             |          |        | 139  | failed      | expected Closed, found Open |
|             |          |        | 443  | failed      | expected Closed, found Open |
|             |          |        | 444  | failed      | expected Open, found Closed |
|             |          |        | 445  | failed      | expected Closed, found Open |
|             |          |        | 465  | failed      | expected Closed, found Open |
|             |          |        | 587  | failed      | expected Closed, found Open |
|             |          |        | 993  | failed      | expected Closed, found Open |
|             |          |        | 3261 | failed      | expected Closed, found Open |
|             |          |        | 5000 | failed      | expected Closed, found Open |
|             |          |        | 5001 | failed      | expected Closed, found Open |
+-------------+----------+--------+------+-------------+-----------------------------+
"##;

    let portspecs =
        PortSpecs::from_file("tests/portspecs.yml").expect("Failed to load portspecs file");
    let mapping =
        Mapping::from_file("tests/portspec_mapping.json").expect("Failed to mappings file");
    let nmap_run = Run::from_file("tests/nmap-dd_all_ports.xml").expect("Failed to load nmap file");
    nmap_run.is_sane().expect("Nmap file is not sane");

    let analyzer_result = default_analysis(&nmap_run, &mapping, &portspecs);

    let output_config = OutputConfig {
        detail: OutputDetail::Fail,
        format: OutputFormat::Human,
        color: false,
    };

    let mut buffer = String::from("\n");
    unsafe {
        analyzer_result
            .output(&output_config, &mut buffer.as_mut_vec())
            .expect("Output failed");
    }

    assert_eq!(buffer.as_str(), expected_output, "Output is correct");
}
