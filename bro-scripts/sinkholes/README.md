DNS Sinkholes
================

This script package provides an extension to dns.log that can be used to track DNS sinkhole requests, provided that the user inserts sinkhole server IP addresses / net blocks in the file sinkhole_ip.dat.

Sample output of dns.log can be seen below:
```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	query	qclasqclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected	sinkhole
1359930253.708622	CHTzdSTuBRxDjyX81	172.16.253.129	53	4.2.2.2	53	udp	48752	www.ald-transports-express.eu	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	195.22.26.231	100.000000	F	T
```

Feature list
---
* Identifies if a DNS request was answered with a sinkhole server

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file
```
@load bro-scripts/sinkholes
```
* Add a list of sinkhole server IP addresses / net blocks to sinkhole_ip.dat

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```
