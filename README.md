# nmap-analyze

Analyzes nmap XML output and compares results with expected specification.

[![Linux and macOS Build Status](https://travis-ci.org/lukaspustina/nmap-analyze.svg?branch=master)](https://travis-ci.org/lukaspustina/nmap-analyze) [![codecov](https://codecov.io/gh/lukaspustina/nmap-analyze/branch/master/graph/badge.svg)](https://codecov.io/gh/lukaspustina/nmap-analyze) [![GitHub release](https://img.shields.io/github/release/lukaspustina/nmap-analyze.svg)](https://github.com/lukaspustina/nmap-analyze/releases) [![](https://img.shields.io/crates/v/nmap-analyze.svg)](https://crates.io/crates/nmap-analyze) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg?label=License)](./LICENSE)

[nmap](https://nmap.org) is highly sophisticated and widely used port scanner. It scan a single host or a group of hosts for open TCP and UDP ports. This allows administrators to verify firewall and host port filter configuration. `nmap-analyze` is a very simplistic tool that helps to ease this verification process. Basically, it takes nmap's scan results as XML and compares the open as well as closed ports for each host scanned to a specification in YAML and reports all deviations. `nmap-analyze` supports both, human readable as well as JSON output. The later can be used for post-processing.

We use run a large number of virtual machines and scan their public IP address daily. By using `nmap-analyze` we can quickly parse the plethora of port scan results and compare them to our expectations. In this way, a misconfiguration of firewalls, security groups, and service settings are quickly discovered before somebody out there can exploit it. 


## Basic Usage

`nmap-analyze` needs three informations: 1. nmap scan results in XML format, 2. a mapping of IP addresses to ports specifications, and 3. the port specifications. The mapping allows you to define groups of hosts that are mapped to the same specification. 


### Run nmap

`nmap-analyze` requires nmap to create an XML output file and to run in debug 2 mode (`-dd`). The debug mode forces nmap to write result for each port; not just the "interesting" ports. For example, you can scan the host with IP address `192.168.0.1` in debug 2 mode (`-dd`), no DNS resolution (`-n`), TCP SYN scan (`-sS`), and XML output to file (`-oX nmap-results.xml`) like this:

```bash
sudo nmap -dd -n -sS -oX nmap-results.xml 192.168.0.1
```


### Ports Specification Mapping

The ports specification mapping maps IP addresses of a host to a corresponding ports specification. In this way, you have an n:1 mapping of ports which drastically reduces the amount of ports specifications when you have multiple hosts with the same role. For example, you could have 5 REST API servers and 3 database servers. The ports specification would require only two specifications, one for each server role. For example, the following mappings defines these two group with their corresponding roles. Only the fields `ips` and `portspec` are mandatory. 

```json
{ "mappings":
    [
        {
            "hostname": "rest01",
            "id": "i-0",
            "ips": ["192.168.0.1"],
            "name": "Rest server 01",
            "portspec": "Rest Server"
        },
        {
            "hostname": "rest02",
            "id": "i-1",
            "ips": ["192.168.0.2"],
            "name": "Rest Server 02",
            "portspec": "Rest Server"
        },
        {
            "hostname": "db01",
            "id": "i-2",
            "ips": ["192.168.0.3", "192.168.0.4"],
            "name": "Db server 01",
            "portspec": "Db Server"
        }
    ]
}
```

The ports specification mapping requires JSON format, because its very easy to generate automatically. For example, we use CLI tools of our public cloud providers to enumerate our virtual machine. Each machine has a public IP address and a tag named "host_group" that states the role of the virtual machine.

For AWS you can try something like this to generate the mappings file. This examples requires the AWS CLI tool and `jq`.

```bash
function jq_filter {
   local root="${1}"

   local id="${2}"
   local hostname="${3}"
   local ips="${4}"
   local name="${5}"
   local portspec="${6}"

   echo "${root} | { id: ${id}, hostname: ${hostname}, ips: ${ips}, name: ${name}, portspec: ${portspec} }"
 }

aws ec2 describe-instances --filters 'Name=instance-state-name,Values=running' --output json | jq -r "$(jq_filter '.Reservations[].Instances[]' '.InstanceId' '.PublicDnsName' '[ .PublicIpAddress ]' '.Tags[] | select(.Key=="Name") .Value' '.Tags[] | select(.Key=="host_group") .Value')" > portspec_mapping.json
```


### Port Specifications

The port specifications file defines which ports must be open, closed, or may be either open or closed. A port specifications file consists of a list of items that have a name which is referenced by the port specification mapping field `portspec`. In this way, multiple hosts can be mapped to the same port specification. The following example shows a port specifications file with two port specifications "Rest Server" and "Db Server":

```yaml
portspecs:
  - name: Rest Server
    ports:
      - id: 22
        state: closed
      - id: 25
        state: maybe
      - id: 443
        state: open
  - name: DB Server
    ports:
      - id: 3306
        state: open
```

The "Rest Server" port specification defines that port 22 (ssh) must be closed and port 443 (https) must be open. Port 25 (smtp) maybe be open or closed. The state "maybe" is useful in situations where a single scan is inconclusive or scan results may vary. For example, AWS sometimes filters scan attempts for port 25. So while the port is technically open, a scan shows it closed from time to time. The "Db Server" port specification requires the port 3306 (mysql) to be open. All other ports that have not been explicitly defined are supposed to be closed.

A port scan usually only probes a limited set of ports instead of scanning all 65535 possible ports to save time. In case, the scan results do not contain a specified port and thus, `nmap-analyze` cannot decide if a port specification is adhered to, it will signal an error. By explicitly specifying a particular port to be closed, you can ensure that `nmap-analyze` will try to check the port.

## Demo

<p align="center"><script src="https://asciinema.org/a/240985.js" id="asciicast-240985" async data-size="small" data-theme="monokai"></script></p>

## Installation

### Ubuntu [x86_64]

Please add my [PackageCloud](https://packagecloud.io/lukaspustina/opensource) open source repository and install `nmap-analyze` via apt.

```bash
curl -s https://packagecloud.io/install/repositories/lukaspustina/opensource/script.deb.sh | sudo bash
sudo apt-get install nmap-analyze
```

### Linux Binaries [x86_64]

There are binaries available at the GitHub [release page](https://github.com/lukaspustina/nmap-analyze/releases). The binaries get compiled on Ubuntu.

### macOS

Please use [Homebrew](https://brew.sh) to install `nmap-analyze` on your system.

```bash
brew install lukaspustina/os/nmap-analyze
```

### macOS Binaries [x86_64]

There are binaries available at the GitHub [release page](https://github.com/lukaspustina/nmap-analyze/releases).

### Sources

Please install Rust via [rustup](https://www.rustup.rs) and then run

```bash
git clone https://github.com/lukaspustina/nmap-analyze
cd nmap-analyze
cargo build
```

  
## Postcardware

You're free to use `nmap-analyze`. If you find it useful, I would highly appreciate you sending me a postcard from your hometown mentioning how you use `nmap-analyze`. My work address is

```
Lukas Pustina
CenterDevice GmbH
Rheinwerkallee 3
53227 Bonn
Germany
```

