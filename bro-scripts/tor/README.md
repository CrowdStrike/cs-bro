Tor server log
================

This script package provides a new log source (tor.log) for network activity involving known Tor servers. When a Tor server is seen as either the originator or responder of a connection, the connection is written to tor.log along with the server's metadata-- metadata includes the server's router name, host name, uptime, and flags. 

Sample output of tor.log can be seen below:
```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	tor_ip	router_name	host_name	platform	country_code	bandwidth	uptime	router_port	directory_port	auth_flag	exit_flag	fast_flag	guard_flag	named_flag	stable_flag	running_flag	valid_flag	v2dir_flag	hibernating_flag	bad_exit_flag
#types	time	string	addr	port	addr	port	addr	string	string	string	string	count	time	count	count	bool	bool	bool	bool	bool	bool	bool	bool	bool	bool	bool
1430771671.379297	C5v6aMBZBvPkEF0Te	10.2.33.76	62731	23.254.167.231	21	23.254.167.231	Pascal9	client-23-254-167-231.hostwindsdns.com	Tor 0.2.5.12 on Linux	US	1783	104400.000000	21	20	F	F	T	F	F
1430771639.088494	Cnh8OF7g4LFrw3i4e	10.2.33.76	8	71.222.54.4	0	71.222.54.4	11not11	71-222-54-4.ptld.qwest.net	Tor 0.2.5.12 on Linux	US	1	612000.000000	9001	9030	F	F	F	F	F	F
```

Additionally, loading the script add-tor.bro creates a new field in conn.log named found_tor-- this field contains a boolean value that describes if a Tor server was seen as either the originator or responder in the connection. This script is provided as an easy way for analysts to pivot to other activity seen over the connection.

Overall, this method of identifying connections involving Tor servers is preferable to traditional IDS detection or treating each Tor node as "bad" and adding them to a watchlist / indicator list-- Tor use in and of itself is not malicious, but the Tor network can be used for malicious purposes; logging this activity and connecting it with other network logs and artifacts allows an analyst to make a determination of whether or not the activity is threatening to their network.

The list of Tor servers is collected from torstatus.blutmagie.de and sent to Bro via the Input framework; while other lists of Tor servers can be used, this script package is written for the list provided by torstatus.blutmagie.de. For highest accuracy, this list should be updated at least once an hour and preferably  closer to once every 20 minutes. An accompanying Python script, scrape-tor.py, is included to collect the list of Tor servers.

Feature list
---
* Identifies Tor servers in network traffic based on publicly declared IP addresses 
* Logs Tor server metadata to tor.log
* Logs Tor connections to tor.log and conn.log
* Adds Tor as a service to conn.log
* Generates an informational message in reporter.log each time Bro loads a new Tor server list
* Tor server list can be updated as frequently as needed (by utilizing scrape-tor.py or a similarly written script)

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/cs-bro.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/tor
```
* As needed, modify the path to the Tor server list (outfile_name in scrape-tor.py)
* As needed, modify the location of the Tor server list in the Bro script (torlist_location in main.bro)

Author
---
```
Josh Liburdi
@jshlbrd
josh.liburdi@crowdstrike.com
```

References
---
* https://en.wikipedia.org/wiki/Tor
* https://torstatus.blutmagie.de
