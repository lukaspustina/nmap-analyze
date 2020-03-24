# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]  

## [1.1.0] - 2020-03-24

### Add
Process multiple addresses per host and ignore MAC addresses.

## [1.0.0] - 2019-04-15

### Added 
Adds 'maybe' as a port specification option. Fixes #2.

### Changed
Bumps minimum Rust version to 1.29 to make use of `std::Iter::Flatten`.

## [0.2.1] - 2018-09-04

### Changed
- Made all struct fields but `ips` and `port_spec` optional in `mapping::Host`
- Fixed a typo in human output

## [0.2.0] - 2018-08-02

### Changed
Refactoring of nmap parser
Refactoring of analyzer components

### Fixed
Fixed parser bug for long nmap xml files containing intermediate task tags; cf. #1.

## [0.1.0] - 2018-07-28

First release

[Unreleased]: https://github.com/lukaspustina/nmap-analyze/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lukaspustina/nmap-analyze/compare/v0.2.1...v1.0.0
[0.2.1]: https://github.com/lukaspustina/nmap-analyze/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lukaspustina/nmap-analyze/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lukaspustina/nmap-analyze/compare/v0.0.2...v0.1.0

