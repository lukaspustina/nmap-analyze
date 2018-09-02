# nmap-analyze

Analyzes nmap XML output and compares results with expected specification.

[![Linux and macOS Build Status](https://travis-ci.org/lukaspustina/nmap-analyze.svg?branch=master)](https://travis-ci.org/lukaspustina/nmap-analyze) [![codecov](https://codecov.io/gh/lukaspustina/nmap-analyze/branch/master/graph/badge.svg)](https://codecov.io/gh/lukaspustina/nmap-analyze) [![GitHub release](https://img.shields.io/github/release/lukaspustina/nmap-analyze.svg)](https://github.com/lukaspustina/nmap-analyze/releases) [![](https://img.shields.io/crates/v/nmap-analyze.svg)](https://crates.io/crates/nmap-analyze) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg?label=License)](./LICENSE)

[nmap](https://nmap.org) is highly sophisticated and widely used port scanner. It scan a single host or a group of hosts for open TCP and UDP ports. This allows administrators to verify firewall and host port filter configuration. `nmap-analyze` is a very simplistic tool that helps to ease this verification process. Basically, it takes nmap's scan results as XML and compares the open as well as closed ports for each host scanned to a specification in YAML and reports all deviations. `nmap-analyze` supports both, human readable as well as JSON output. The later can be used for post-processing.

We use run a large number of virtual machines and scan their public IP address daily. By using `nmap-analyze` we can quickly parse the plethora of port scan results and compare them to our expectations. In this way, a misconfiguration of firewalls, security groups, and service settings are quickly discovered before somebody out there can exploit it. 


## Basic Usage

`nmap-analyze` needs three informations: 1. nmap scan results in XML format, 2. a mapping of an IP address to its ports specification, and 3. the port specification. The mapping allows you to define groups of hosts that are all mapped to the same specification. 


### Run nmap

`nmap-analyze` requires nmap to create an XML output file and to run in debug 2 mode (`-dd`). The debug mode forces nmap to write result for each port; not just the "interesting" ports. For example, you can scan the host with IP address `192.168.0.1` in debug 2 mode (`-dd`), no DNS resolution (`-n`), TCP SYN scan (`-sS`), and XML output to file (`-oX nmap-results.xml`) like this:

```
sudo nmap -dd -n -sS -oX nmap-results.xml 192.168.0.1
```


### Ports Specification Mapping

The ports specification mapping maps IP addresses of a host to a corresponding ports specification. In this way, you an have an n:1 mapping of ports which drastically reduced the amount of ports specifications when you have multiple hosts with the same role. For example, you could have 5 REST API servers and 3 database servers. The ports specification would require only two specifications, one for each server role. For example, the following mappings defines these two group with their corresponding roles. Only the fields `ips` and `portspec` are mandatory. 

```
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

The ports specification mapping requires JSON format, because its very easy to generate automatically. For example, we use the CLI tools of our public cloud providers to enumerate our virtual machine. Each machine has a public IP address and a tag named "host_group" that states the role of the virtual machine.

For AWS you can try something like this to generate the mappings file:

```
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


### Port Specification


## Demo


## Installation


## Analyzer Algorithm


## Todos

1. Fill Readme

