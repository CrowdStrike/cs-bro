Tracked Provider log
================

This script package provides a new log source (tracked_provider.log) for network activity involving VPS and VPN servers that the user determines to be worth tracking. When a "tracked provider" server is seen as either the originator or responder of a connection, the connection is written to tracked_provider.log along with the provider's metadata (the provider name and the server type).

Additionally, loading the script add-provider.bro creates a new field in conn.log named found_tracked_provider-- this field contains a boolean value that describes if a tracked provider server was seen as either the originator or responder in the connection. This script is provided as an easy way for analysts to pivot to other activity seen over the connection.


Feature list
---
* Identifies tracked servers in network traffic
* Logs tracked server metadata to tracked_provider.log
* Logs tracked server connections to tor.log and conn.log

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/tracked_providers
```
* As needed, modify the names / paths to the tracked provider files. 

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```
