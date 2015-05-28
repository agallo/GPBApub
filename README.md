# GetPrefixByASN - GPBA

This script will report all prefixes advertised by the provided Autonomous System Number (ASN) and provide
summary information.

Requirements:

 - [Juniper PyEZ](https://techwiki.juniper.net/Automation_Scripting/010_Getting_Started_and_Reference/Junos_PyEZ/Installation)
 - [pythonwhois](http://cryto.net/pythonwhois/index.html)
 
 
Usage:

usage: GPBA.py [-h] [-a {4,6}] [-c] [-l] [-s] [-t] 2byte/4byte ASN

Script to pull prefixes advertised by (or through)A given ASN

positional arguments:

  2byte/4byte ASN

optional arguments:

  -h, --help            show this help message and exit

  -a {4,6}, --addr_family {4,6}
                        Address family. -a 4 force v4 only, -a 6 force v6 
                        only. (Default is both)

  -c, --combine         put both address families in the same file. (Default is separate files)

  -l, --lookupASN       Lookup name of ASN via cymru whois. (Default is don't lookup)

  -s, --summarize       Provide a summary of hosts & /24 (v4) /64 (v4) represented by prefixes (Default is not to summarize)

  -t, --include-transit Include transit routes in query. Changes regex from "ASN" to ".* ASN .*" (Default is do not include transit)




Currently, IP of the target router and authentication data are hardcoded; future release will allow passing that 
information via command arguments.

