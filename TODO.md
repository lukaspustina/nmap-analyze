# TODO

1. Replace all examples with full port output (-dd)
1. Check Nmap xml output if -dd has been specified and if not reject processing
    1. Same goes for extraports
1. Change whitelist name to specification
1. Create Readme
    1. Describe algorithm: Port is considered open when "open" or "open|filtered". -- That may be changed via cli parameter, same goes for close.
1. How do we handle "filtered"?
    1. Is this equivalent to "closed"?
    1. Shall we make this part of the configuration? 

