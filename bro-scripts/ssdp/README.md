SSDP parser
================

This script provides a simple method of parsing SSDP traffic. Parsed SSDP data is logged to ssdp.log, and includes request and response search targets, UPnP device data, and more. 

Technical details
---
The script uses the Signature framework (deep packet inspection) to identify SSDP traffic. Traffic is identified by inspecting UDP traffic containing one of two HTTP requests (NOTIFY or M-SEARCH) or an HTTP 200 OK response in the first line of the payload. The remaining payload follows the convention of a standard HTTP header by having a header field and value separated by a colon (e.g., HEADER: VALUE). A function splits the payload based on predictable values and parses the header fields and values into a table; this table is iterated over and specific data in the table is logged.

Note that this is not the ideal way to handle this traffic; ideally this would be a parser written in core (C++), but this script is a proof-of-concept to see if it is worth the effort of writing a native parser. 

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/NetworkDetection.git
```
* Add the directory to the local.bro file 
```
@load bro-scripts/ssdp
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
* http://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol
* http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20080424.pdf
