extern crate nmap_analyze;
extern crate spectral;

mod nmap {
    use nmap_analyze::{FromFile, Run, SanityCheck};

    use spectral::prelude::*;
    use std::path::Path;

    #[test]
    fn read_unsane_file() {
        let file = Path::new("tests/nmap-3hosts-result.xml");
        let res = Run::from_file(file);

        assert_that(&res).is_ok();
        let run = res.unwrap();
        assert_that(&run.is_sane()).is_err();
    }

    #[test]
    fn read_sane_file() {
        let file = Path::new("tests/nmap-dd_all_ports.xml");
        let res = Run::from_file(file);

        assert_that(&res).is_ok();
        let run = res.unwrap();
        assert_that(&run.is_sane()).is_ok();
    }

    #[test]
    fn read_serde_xml_rs_issue_55_file() {
        let file = Path::new("tests/nmap-result-parser_failed-55.xml");
        let res = Run::from_file(file);

        assert_that(&res).is_ok();
        let run = res.unwrap();
        assert_that(&run.is_sane()).is_ok();
    }

    #[test]
    fn read_sane_file_with_mac_addr_issue_3() {
        let file = Path::new("tests/nmap-mac_addresses.xml");
        let res = Run::from_file(file);

        assert_that(&res).is_ok();
        let run = res.unwrap();
        assert_that(&run.is_sane()).is_ok();
    }

    #[test]
    fn read_sane_file_with_host_no_response() {
        let file = Path::new("tests/nmap-host-no-response-result.xml");
        let res = Run::from_file(file);

        assert_that(&res).is_ok();
        let run = res.unwrap();
        assert_that(&run.is_sane()).is_ok();
    }

}

mod mapping {
    use nmap_analyze::{FromFile, Mapping};

    use spectral::prelude::*;
    use std::path::Path;

    #[test]
    fn read_file() {
        let file = Path::new("tests/portspec_mapping.json");
        let res = Mapping::from_file(file);

        assert_that(&res).is_ok();
        let mapping = res.unwrap();
        assert_that(&mapping.mappings).has_length(3);
    }
}

mod portspec {
    use nmap_analyze::{FromFile, PortSpecs};

    use spectral::prelude::*;
    use std::path::Path;

    #[test]
    fn read_file() {
        let file = Path::new("tests/portspecs.yml");
        let res = PortSpecs::from_file(file);

        assert_that(&res).is_ok();
        let portspecs = res.unwrap();
        assert_that(&portspecs.port_specs).has_length(2);
    }
}
