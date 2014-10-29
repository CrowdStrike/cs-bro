Mac.BackDoor.iWorm detector
================

This script provides detection for the C2 acquisition phase of the Mac.BackDoor.iWorm backdoor described by Dr. Web. Prior to the establishment of C2 channels, the backdoor connects to reddit.com and accesses specific pages to collect IP addresses that will be used for the C2 communication. The backdoor accesses these pages by searching for 8 bytes of the MD5 hash of the current date. 

The script detects this behavior by identifying endpoints connecting to and searching reddit.com, extracting the search value from the request URI, and verifying that the search value is an 8 byte MD5 hash. If detected, the script generates a notice that provides connections details (net flow) as well as the full URI requested by the endpoint.

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/NetworkDetection.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/mac-backdoor-iworm/detect-mac-iworm
```

Author
---
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com

References
---
* http://news.drweb.com/show/?i=5976&lng=en&c=14
