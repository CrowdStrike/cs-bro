DCE-RPC log
================

This script package provides a new log source (dce_rpc.log) for network activity that involves DCE-RPC traffic. The log contains metadata for the UUID of the binding interface, the opnum, the message type, and the stub length of each DCE-RPC request / response. A descriptive name for many binding interface UUIDs are also included.

Sample output of dce_rpc.log can be seen below:
```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	int_uuid	int_uuid_desc	opnum	msg_type	stub_len
#types	time	string	addr	port	addr	port	string	string	count	string	count
1446662753.000867	C5EnJ41yxdd4pTmVwj	192.168.132.142	26387	192.168.142.207	49154	9556dc99-828c-11cf-a37e-00aa003240c7	IWbemServices	20	REQUEST	248
1446662753.026952	C5EnJ41yxdd4pTmVwj	192.168.132.142	26387	192.168.142.207	49154	9556dc99-828c-11cf-a37e-00aa003240c7	IWbemServices	20	RESPONSE	216
1446662753.031178	C5EnJ41yxdd4pTmVwj	192.168.132.142	26387	192.168.142.207	49154	9556dc99-828c-11cf-a37e-00aa003240c7	IWbemServices	3	REQUEST	104
1446662753.034940	C5EnJ41yxdd4pTmVwj	192.168.132.142	26387	192.168.142.207	49154	9556dc99-828c-11cf-a37e-00aa003240c7	IWbemServices	3	RESPONSE	88
```

Feature list
---
* Logs metadata from DCE-RPC network traffic
* Logs a descriptive name for multiple binding interface UUIDs

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file
```
@load bro-scripts/dce_rpc
```

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```
