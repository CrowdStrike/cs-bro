Shellshock exploitation detector
================

This script provides detection for the widely documented Bash exploit "shellshock." Shellshock exploitation can be achieved multiple ways over many services-- this script performs pattern matching on common strings in exploit attempts and identifies exploits seen over HTTP, DHCP, and SMTP. If an exploit attempt is seen, then the script generates a notice that provides connection details (net flow), what service the exploit was seen on, and the exploit attempted.

This script also addresses the issue of not knowing if an exploit attempt was successful by monitoring for network activity related to each attempt. Many attackers exploiting shellshock use it to verify connectivity to exploitable endpoints or to download malicious files to exploitable endpoints by redirecting the endpoint to an external host. To verify successful exploitation, the script parses each exploit attempt for IP address and domain values and, if found, extracts the values and monitors for any endpoint to connect to them. There is a 1-hour time window on each IP address and domain seen in exploit attempts, allowing each malicious IP address and domain to only be monitored when ncessary. (This 1-hour time window can be shortened or lengthened by modifying the script.) If an endpoint connects to an IP address or domain seen in an exploit attempt, then there is a high chance that successful exploitation occurred; when this happens, the script generates a notice that provides connection details (net flow) and the malicious IP address or domain the endpoint connected to. 

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/NetworkDetection.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/shellshock/detect-shellshock
```

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```

References
---
* http://blog.crowdstrike.com/mitigating-bash-shellshock/
* http://en.wikipedia.org/wiki/Shellshock_(software_bug)
