extern crate nmap_analyze;
extern crate spectral;

use nmap_analyze::{Run, SanityCheck};

use spectral::prelude::*;
use std::io::prelude::*;
use std::fs::File;
use std::str::FromStr;

#[test]
fn read_unsane_file() {
    let mut file = File::open("tests/nmap-3hosts-result.xml").expect("Unable to open nmap file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read nmap file");

    let run: Run = Run::from_str(&contents).expect("Could not parse nmap file");

    assert_that(&run.is_sane()).is_err();
}

#[test]
fn read_sane_file() {
    let mut file = File::open("tests/nmap-dd_all_ports.xml").expect("Unable to open nmap file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read nmap file");

    let run: Run = Run::from_str(&contents).expect("Could not parse nmap file");

    assert_that(&run.is_sane()).is_ok();
}
