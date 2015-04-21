MS15-034 detector
================

This script provides detection for activity related to the MS15-034 vulnerability (buffer overflow with remote code execution possibilities).

MS15-034 vulnerabilities can be identified by monitoring inbound HTTP traffic for requests that have a byte range that is out of range for the web server to accommodate (in this case, a range up to 18446744073709551615 will trigger the exploit). The web server is vulnerable if it responds with status code 416. The notice included in this script will trigger on any inbound HTTP requests that include a client RANGE header and a server response code of 416; the notice will also trigger if the server does not respond at all (this may indicate that the web server crashed as a result of the exploit). The RANGE value, which is the range of bytes requested by the client, is included in the notice so that an analyst can quickly decide whether the traffic is malicious or benign.

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/msb
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
* https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
* https://ma.ttias.be/remote-code-execution-via-http-request-in-iis-on-windows/
