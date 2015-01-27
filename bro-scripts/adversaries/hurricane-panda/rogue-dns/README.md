Rogue DNS detector
================

These scripts provide detection for a rogue DNS tactic utilized by Hurricane Panda. You can read more about this tactic on the CrowdStrike blog: http://blog.crowdstrike.com/storm-chasing/

Detection of this tactic relies heavily on having a list of common, known-good domains. To fill this need, these scripts use  the top 500 global domains as reported by Alexa (alexa.com/topsites). One script (static/detect-rogue-dns.bro) includes a static list of domains gathered from Alexa and can be deployed with no other dependencies. The other script (dynamic/detect-rogue-dns.bro) depends on a Python script (dynamic/scrape-alexa.py) that automates the collection of Alexa domains; this Python script should be scheduled to run regularly (daily, weekly, etc) so that the list of domains is kept up-to-date and the output file (alexa_domains.txt) should be pushed to network sensors along with the Bro script. Aside from the operation of collecting domains, both scripts are identical and contain the same detection capabilities.

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/NetworkDetection.git
```
* Add one of the two scripts to the local.bro file 
```
@load bro-scripts/adversaries/hurricane-panda/rogue-dns/dynamic/detect-rogue-dns.bro
@load bro-scripts/adversaries/hurricane-panda/rogue-dns/static/detect-rogue-dns.bro
```
* If dynamic/detect-rogue-dns is deployed... 
* Add scrape-alexa.py as cron job 
```
0 0 * * * /usr/bin/python .../scrape-alexa.py
```
* Edit scrape-alexa.py output file location as needed
```
f = open('your/cool/new/file/location/alexa_domains.txt','w')
```
* Redefine alexa_file location in local.bro as needed
```
@load bro-scripts/adversaries/hurricane-panda/rogue-dns/static/detect-rogue-dns.bro
redef CrowdStrike::Hurricane_Panda::alexa_file = "your/cool/new/file/location/alexa_domains.txt";
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
http://blog.crowdstrike.com/storm-chasing/
