# GetPrefixByASN - GPBA

This script will report all prefixes advertised by the provided Autonomous System Number (ASN) and provide
summary information.

Requirements:

 - [Juniper PyEZ](https://techwiki.juniper.net/Automation_Scripting/010_Getting_Started_and_Reference/Junos_PyEZ/Installation)
 - [pythonwhois](http://cryto.net/pythonwhois/index.html)
 

 ````
usage: GPBA.py [-h] [-a {4,6}] [-c] [-l] [-s] [-t] [-u USER] [-k KEY]
               ASN target_router

Script to pull prefixes advertised by (or through) a given ASN

positional arguments:
  ASN
  target_router

optional arguments:
  -h, --help            show this help message and exit
  -a {4,6}, --addr_family {4,6}
                        Address family. -a 4 force v4 only, -a 6 force v6
                        only. (Default is both
  -c, --combine         put both address families in the same file. (Default
                        is separate files
  -l, --lookupASN       Lookup name of ASN via cymru whois. (Default is don't
                        lookup)
  -s, --summarize       Provide a summary of hosts & /24 (v4) /64 (v4)
                        represented by prefixes (Default is not to summarize)
  -t, --transit         Include transit routes in query. Changes regex from
                        ".* ASN" to ".* ASN .*" (Default is do not include
                        transit
  -u USER, --user USER  username for router authentication (specify if
                        different than current shell user)
  -k KEY, --key KEY     full path to ssh private key (specify if different
                        than current shell user
````

A note on authentication:
The default behavior (with no -u or -k) assumes the username and private key of the shell user running the script.
The assumption is that this user has at least read-only privileges to the specified router.
You can specify a different user and key file.  The script doesn't require these flags be passed together, but that 
is generally how they would be used.

Currently, password authentication isn't supported, though it wouldn't be hard to add.

