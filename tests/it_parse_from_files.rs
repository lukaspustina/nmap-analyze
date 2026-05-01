mod nmap {
    use nmap_analyze::{FromFile, Run, SanityCheck};

    use std::path::Path;

    #[test]
    fn read_unsane_file() {
        let file = Path::new("tests/nmap-3hosts-result.xml");
        let run = Run::from_file(file).expect("file load failed");
        assert!(run.is_sane().is_err());
    }

    #[test]
    fn read_sane_file() {
        let file = Path::new("tests/nmap-dd_all_ports.xml");
        let run = Run::from_file(file).expect("file load failed");
        assert!(run.is_sane().is_ok());
    }

    #[test]
    fn read_serde_xml_rs_issue_55_file() {
        let file = Path::new("tests/nmap-result-parser_failed-55.xml");
        let run = Run::from_file(file).expect("file load failed");
        assert!(run.is_sane().is_ok());
    }

    #[test]
    fn read_sane_file_with_mac_addr_issue_3() {
        let file = Path::new("tests/nmap-mac_addresses.xml");
        let run = Run::from_file(file).expect("file load failed");
        assert!(run.is_sane().is_ok());
    }

    #[test]
    fn read_sane_file_with_host_no_response() {
        let file = Path::new("tests/nmap-host-no-response-result.xml");
        let run = Run::from_file(file).expect("file load failed");
        assert!(run.is_sane().is_ok());
    }
}

mod mapping {
    use nmap_analyze::{FromFile, Mapping};

    use std::path::Path;

    #[test]
    fn read_file() {
        let file = Path::new("tests/portspec_mapping.json");
        let mapping = Mapping::from_file(file).expect("file load failed");
        assert_eq!(mapping.mappings.len(), 3);
    }
}

mod portspec {
    use nmap_analyze::{FromFile, PortSpecs};

    use std::path::Path;

    #[test]
    fn read_file() {
        let file = Path::new("tests/portspecs.yml");
        let portspecs = PortSpecs::from_file(file).expect("file load failed");
        assert_eq!(portspecs.port_specs.len(), 2);
    }
}
