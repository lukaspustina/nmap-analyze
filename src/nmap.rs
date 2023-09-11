use super::{from_str, FromFile, SanityCheck};

use std::net::IpAddr;
use std::str::FromStr;

error_chain! {
    errors {
        InvalidNmapFile {
            description("invalid nmap file")
        }
        InsaneNmapFile(reason: String) {
            description("invalid nmap file")
            display("invalid nmap file because {}", reason)
        }
        InvalidHostState(invalid: String) {
            description("invalid host state")
            display("invalid host state: {}", invalid)
        }
        InvalidHostNameType(invalid: String) {
            description("invalid hostname type")
            display("invalid hostname type: {}", invalid)
        }
        InvalidPortStatus(invalid: String) {
            description("invalid port status")
            display("invalid port status: {}", invalid)
        }
    }
}

#[derive(Debug)]
pub struct Run {
    pub scanner: String,
    pub args: String,
    pub start: u64,
    pub hosts: Vec<Host>,
}

impl FromStr for Run {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        parser::Run::from_str(s).map(Run::from)
    }
}

impl From<parser::Run> for Run {
    fn from(p_run: parser::Run) -> Run {
        let hosts: Vec<Host> = p_run
            .hosts
            .into_iter()
            .map(|x| match x {
                parser::RunElement::Host(host) => Some(host),
                _ => None,
            })
            .flatten()
            .map(Host::from)
            .collect();
        Run {
            scanner: p_run.scanner,
            args: p_run.args,
            start: p_run.start,
            hosts,
        }
    }
}

impl FromFile for Run {}

impl SanityCheck for Run {
    type Error = Error;

    fn is_sane(&self) -> Result<()> {
        if !self.has_dd_options() {
            return Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                "nmap has been run without -dd option; use nmap -dd ..".to_owned(),
            )));
        }

        for host in &self.hosts {
            host.is_sane()?;
        }

        Ok(())
    }
}

impl Run {
    fn has_dd_options(&self) -> bool {
        self.args.contains("-dd")
    }
}

#[derive(Debug)]
pub struct Host {
    pub starttime: usize,
    pub endtime: usize,
    pub status: HostStatus,
    pub addresses: Vec<Address>,
    pub hostnames: Vec<HostName>,
    pub ports: Vec<Port>,
    pub extra_ports: Option<Vec<ExtraPorts>>,
}

impl From<parser::Host> for Host {
    fn from(p_host: parser::Host) -> Host {
        let ports = p_host.ports.ports.into_iter().map(Port::from).collect();
        Host {
            starttime: p_host.starttime,
            endtime: p_host.endtime,
            status: p_host.status,
            addresses: p_host.addresses,
            hostnames: p_host.hostnames.hostnames,
            ports,
            extra_ports: p_host.ports.extra_ports,
        }
    }
}

impl SanityCheck for Host {
    type Error = Error;

    fn is_sane(&self) -> Result<()> {
        if self.has_extra_ports() {
            return Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                "Host has extraports defined; use nmap -dd ...".to_owned(),
            )));
        }
        if self.addresses.is_empty() {
            return Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                "Host has no addresses".to_owned(),
            )));
        }
        if !self.addresses.iter().any(|addr| match addr {
            Address::IpV4 { .. } => true,
            _ => false,
        }) {
            return Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                "Host has no IP address".to_owned(),
            )));
        }

        Ok(())
    }
}

impl Host {
    fn has_extra_ports(&self) -> bool {
        self.extra_ports.is_some()
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "addrtype")]
pub enum Address {
    #[serde(rename = "ipv4")]
    IpV4 {
        #[serde(deserialize_with = "from_str")]
        addr: IpAddr,
    },
    #[serde(rename = "mac")]
    Mac { addr: String },
}

#[derive(Debug, Deserialize)]
pub struct HostStatus {
    #[serde(deserialize_with = "from_str")]
    pub state: HostState,
    pub reason: String,
    #[serde(deserialize_with = "from_str")]
    pub reason_ttl: usize,
}

// cf. nmap.dtd
#[derive(Debug, Deserialize)]
pub enum HostState {
    Up,
    Down,
    Unknown,
    Skipped,
}

impl FromStr for HostState {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "up" => Ok(HostState::Up),
            "down" => Ok(HostState::Down),
            "unknown" => Ok(HostState::Unknown),
            "skipped" => Ok(HostState::Skipped),
            _ => Err(Error::from_kind(ErrorKind::InvalidHostState(s))),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HostName {
    pub name: String,
    #[serde(rename = "type", deserialize_with = "from_str")]
    pub typ: HostNameType,
}

// cf. nmap.dtd
#[derive(Debug, Deserialize)]
pub enum HostNameType {
    User,
    Ptr,
}

impl FromStr for HostNameType {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "user" => Ok(HostNameType::User),
            "ptr" => Ok(HostNameType::Ptr),
            _ => Err(Error::from_kind(ErrorKind::InvalidHostNameType(s))),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExtraPorts {
    #[serde(deserialize_with = "from_str")]
    pub state: PortStatus,
    #[serde(deserialize_with = "from_str")]
    pub count: u16,
}

#[derive(Debug)]
pub struct Port {
    pub protocol: String,
    pub id: u16,
    pub service: PortService,
    pub status: PortStatus,
    pub reason: String,
    pub reason_ttl: usize,
}

impl From<parser::Port> for Port {
    fn from(p_port: parser::Port) -> Port {
        Port {
            protocol: p_port.protocol,
            id: p_port.id,
            service: p_port.service,
            status: p_port.state.state,
            reason: p_port.state.reason,
            reason_ttl: p_port.state.reason_ttl,
        }
    }
}

// cf. nmap.dtd
#[derive(Debug, Deserialize, PartialEq)]
pub enum PortStatus {
    Open,
    Filtered,
    Unfiltered,
    Closed,
    OpenFiltered,
    CloseFiltered,
}

impl FromStr for PortStatus {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "open" => Ok(PortStatus::Open),
            "filtered" => Ok(PortStatus::Filtered),
            "unfiltered" => Ok(PortStatus::Unfiltered),
            "closed" => Ok(PortStatus::Closed),
            "open|filtered" => Ok(PortStatus::OpenFiltered),
            "close|filtered" => Ok(PortStatus::CloseFiltered),
            _ => Err(Error::from_kind(ErrorKind::InvalidPortStatus(s))),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortService {
    pub name: String,
    pub method: String,
    #[serde(deserialize_with = "from_str")]
    pub conf: usize,
}

mod parser {
    use super::*;

    use serde_xml_rs;

    #[derive(Debug, Deserialize)]
    pub struct Run {
        pub scanner: String,
        pub args: String,
        #[serde(deserialize_with = "from_str")]
        pub start: u64,
        #[serde(rename = "$value")]
        pub hosts: Vec<RunElement>,
    }

    impl FromStr for Run {
        type Err = Error;

        fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
            Run::from_bytes(s.as_bytes())
        }
    }

    impl Run {
        fn from_bytes(buffer: &[u8]) -> Result<Self> {
            let run = serde_xml_rs::deserialize(buffer);
            match run {
            Ok(x) => Ok(x),
            // cf. `Host#Address`
            Err(serde_xml_rs::Error::Custom(ref s)) if s == "duplicate field `address`" =>
                Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                "could not parse file, because parser currently supports only one address per host".to_owned()))),
            Err(e) => Err(Error::from_kind(ErrorKind::InsaneNmapFile(
                format!("could not parse file, because {}", e)))),
        }
        }
    }

    // cf. ELEMENT nmaprun in nmap.dtd
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum RunElement {
        ScanInfo(StructInfo),
        Verbose(Verbose),
        Debugging(Debugging),
        Target(Target),
        TaskBegin(TaskBegin),
        TaskProgress(TaskProgress),
        TaskEnd(TaskEnd),
        Prescript(Prescript),
        Postscript(Postscript),
        Host(Host),
        Output(Output),
        RunStats(RunStats),
    }

    #[derive(Debug, Deserialize)]
    pub struct StructInfo {}

    #[derive(Debug, Deserialize)]
    pub struct Verbose {}

    #[derive(Debug, Deserialize)]
    pub struct Debugging {}

    #[derive(Debug, Deserialize)]
    pub struct Target {}

    #[derive(Debug, Deserialize)]
    pub struct TaskBegin {}

    #[derive(Debug, Deserialize)]
    pub struct TaskProgress {}

    #[derive(Debug, Deserialize)]
    pub struct TaskEnd {}

    #[derive(Debug, Deserialize)]
    pub struct Prescript {}

    #[derive(Debug, Deserialize)]
    pub struct Postscript {}

    #[derive(Debug, Deserialize)]
    pub struct Host {
        #[serde(deserialize_with = "from_str", default)]
        pub starttime: usize,
        #[serde(deserialize_with = "from_str", default)]
        pub endtime: usize,
        pub status: HostStatus,
        #[serde(rename = "address")]
        pub addresses: Vec<Address>,
        #[serde(default)]
        pub hostnames: HostNames,
        #[serde(default)]
        pub ports: Ports,
    }

    #[derive(Debug, Deserialize)]
    pub struct Output {}

    #[derive(Debug, Deserialize)]
    pub struct RunStats {}

    #[derive(Debug, Default, Deserialize)]
    pub struct HostNames {
        #[serde(rename = "hostname", default)]
        pub hostnames: Vec<HostName>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct Ports {
        #[serde(rename = "extraports")]
        pub extra_ports: Option<Vec<ExtraPorts>>,
        #[serde(rename = "port", default)]
        pub ports: Vec<Port>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Port {
        pub protocol: String,
        #[serde(rename = "portid", deserialize_with = "from_str")]
        pub id: u16,
        pub state: PortState,
        pub service: PortService,
    }

    #[derive(Debug, Deserialize)]
    pub struct PortState {
        #[serde(deserialize_with = "from_str")]
        pub state: PortStatus,
        pub reason: String,
        #[serde(deserialize_with = "from_str")]
        pub reason_ttl: usize,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use serde_xml_rs;
        use spectral::prelude::*;

        #[test]
        fn parse_host_extraports() {
            let s = r##"
        <host starttime="1531991145" endtime="1531991167">
          <status state="up" reason="user-set" reason_ttl="0"/>
          <address addr="192.168.0.1" addrtype="ipv4"/>
          <hostnames>
            <hostname name="192.168.0.1" type="user"/>
          </hostnames>
          <ports>
            <extraports state="filtered" count="997">
              <extrareasons reason="no-responses" count="997"/>
            </extraports>
            <port protocol="tcp" portid="25">
              <state state="open" reason="syn-ack" reason_ttl="244"/>
              <service name="smtp" method="table" conf="3"/>
            </port>
            <port protocol="tcp" portid="80">
              <state state="closed" reason="reset" reason_ttl="244"/>
              <service name="http" method="table" conf="3"/>
            </port>
            <port protocol="tcp" portid="443">
              <state state="open" reason="syn-ack" reason_ttl="244"/>
              <service name="https" method="table" conf="3"/>
            </port>
          </ports>
          <times srtt="9740" rttvar="1384" to="100000"/>
        </host>
      "##;

            let p_host: parser::Host = serde_xml_rs::deserialize(s.as_bytes()).unwrap();
            let host: super::super::Host = p_host.into();

            assert_that(&host.is_sane()).is_err();
        }

        #[test]
        fn parse_host_with_multiple_addresses() {
            let s = r##"
        <host starttime="1531991145" endtime="1531991167">
          <status state="up" reason="user-set" reason_ttl="0"/>
          <address addr="192.168.0.1" addrtype="ipv4"/>
          <address addr="00:11:DD:5D:2E:DD" addrtype="mac" vendor="Synology Incorporated"/>
          <hostnames>
            <hostname name="192.168.0.1" type="user"/>
          </hostnames>
          <ports>
            <extraports state="filtered" count="997">
              <extrareasons reason="no-responses" count="997"/>
            </extraports>
            <port protocol="tcp" portid="25">
              <state state="open" reason="syn-ack" reason_ttl="244"/>
              <service name="smtp" method="table" conf="3"/>
            </port>
            <port protocol="tcp" portid="80">
              <state state="closed" reason="reset" reason_ttl="244"/>
              <service name="http" method="table" conf="3"/>
            </port>
            <port protocol="tcp" portid="443">
              <state state="open" reason="syn-ack" reason_ttl="244"/>
              <service name="https" method="table" conf="3"/>
            </port>
          </ports>
          <times srtt="9740" rttvar="1384" to="100000"/>
        </host>
      "##;

            let p_host: parser::Host = serde_xml_rs::deserialize(s.as_bytes()).unwrap();
            let host: super::super::Host = p_host.into();

            assert_that(&host.is_sane()).is_err();
        }

        #[test]
        fn parse_no_dd_okay() {
            let s = NMAP_NO_DD_DATA;
            let nmaprun: parser::Run = serde_xml_rs::deserialize(s.as_bytes()).unwrap();
            println!("{:#?}", nmaprun);
        }

        #[test]
        fn no_dd_data_is_insane() {
            let s = NMAP_NO_DD_DATA;
            let p_run: parser::Run = serde_xml_rs::deserialize(s.as_bytes()).unwrap();
            let nmaprun: super::super::Run = p_run.into();

            assert_that(&nmaprun.is_sane()).is_err();
        }

        const NMAP_NO_DD_DATA: &str = r##"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.70 scan initiated Thu Jul 19 11:05:45 2018 as: nmap -v -n -Pn -T4 -sS -oX nmap-3hosts-result.xml 192.168.0.1 192.168.0.2 192.168.0.3 -->
<nmaprun scanner="nmap" args="nmap -v -n -Pn -T4 -sS -oX nmap-3hosts-result.xml 192.168.0.1 192.168.0.2 192.168.0.3" start="1531991145" startstr="Thu Jul 19 11:05:45 2018" version="7.70" xmloutputversion="1.04">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <taskbegin task="SYN Stealth Scan" time="1531991145"/>
  <taskend task="SYN Stealth Scan" time="1531991170" extrainfo="3000 total ports"/>
  <host starttime="1531991145" endtime="1531991167">
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="192.168.0.1" type="user"/>
    </hostnames>
    <ports>
      <extraports state="filtered" count="997">
        <extrareasons reason="no-responses" count="997"/>
      </extraports>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="smtp" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" reason_ttl="244"/>
        <service name="http" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
    <times srtt="9740" rttvar="1384" to="100000"/>
  </host>
  <host starttime="1531991145" endtime="1531991167">
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.0.2" addrtype="ipv4"/>
    <hostnames>
      <hostname name="192.168.0.2" type="user"/>
    </hostnames>
    <ports>
      <extraports state="filtered" count="997">
        <extrareasons reason="no-responses" count="997"/>
      </extraports>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="smtp" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" reason_ttl="244"/>
        <service name="http" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
    <times srtt="9649" rttvar="1802" to="100000"/>
  </host>
  <host starttime="1531991145" endtime="1531991170">
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.0.2" addrtype="ipv4"/>
    <hostnames>
      <hostname name="192.168.0.3" type="user"/>
    </hostnames>
    <ports>
      <extraports state="filtered" count="998">
        <extrareasons reason="no-responses" count="998"/>
      </extraports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="http" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="244"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
    <times srtt="8796" rttvar="1725" to="100000"/>
  </host>
  <runstats>
    <finished time="1531991170" timestr="Thu Jul 19 11:06:10 2018" elapsed="24.53" summary="Nmap done at Thu Jul 19 11:06:10 2018; 3 IP addresses (3 hosts up) scanned in 24.53 seconds" exit="success"/>
    <hosts up="3" down="0" total="3"/>
  </runstats>
</nmaprun>
        "##;
    }
}
