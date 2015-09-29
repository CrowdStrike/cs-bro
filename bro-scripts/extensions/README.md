Logging Extensions
================

This script package includes logging extensions for multiple protocol analyzers / frameworks. Each extension is summarized below.

DNS
---
#### expand-query.bro

This extension adds two new fields to dns.log: a vector of the DNS query without dot separation (query_vec) and the size of the vector (query_vec_size). This provides direct access to each element in the DNS query (top-level domain, domain, subdomain). The original motivation for this extension was to fulfill the need to search and match specific domains without wildcarding the entire DNS query. 

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file
```
@load bro-scripts/extensions
```
* By default, all extensions will be loaded

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```
