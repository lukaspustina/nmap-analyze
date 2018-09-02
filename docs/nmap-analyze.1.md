# NAME

nmap-analyze -- Analyzes nmap xml output and compares results with expected specification.


# SYNOPSIS

nmap-analyze [*options*] *MODULE*

nmap-analyze --help

nmap-analyze --version


# DESCRIPTION

nmap-analyze is a CLI tool that analyzes nmap xml output and compares results with expected specification.

The project home page currently *https://github.com/lukaspustina/nmap-analyze*.


# COMMON OPTIONS

-m, --mapping *mapping*
: Mapping file

-n, --nmap *nmap*
: Nmap XML file

--output-detail *output_detail*
: Select output detail level for human output [default: fail]  [possible values: fail, all]

-o, --output *output_format*
: Select output format [default: human]  [possible values: human, json, none]

-p, --portspec *portspec*
: Portspec file

-v, --verbose
: Verbose mode (-v, -vv, -vvv, etc.)

--help
: Prints help information


# LESS COMMON OPTIONS

--no-color
: Turns off colorful output. Helpful for non-tty usage.

-s, --silent
: Silencium; use this for json output.

-V, --version
: Prints version information.


# COPYRIGHT AND LICENSE

Copyright (c) 2018 Lukas Pustina. Licensed under the MIT License. See *https://github.com/lukaspustina/nmap-analyze/blob/master/LICENSE* for details.

