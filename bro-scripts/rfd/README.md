Reflected File Download detector
================

This script provides detection for reflected file download (RFD) exploitation attempts, as described by Oren Hafif in this presentation from Black Hat Europe 2014: https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf

RFD exploits are detected in this script by inspecting two portions of an HTTP transaction: the requested URI and the server header CONTENT-TYPE. The URI is inspected for patterns associated with RFD exploits and the server CONTENT-TYPE is inspected for headers that can be exploited; detection is also initiated if no CONTENT-TYPE header exists. The script generates an alert in notice.log if a potential reflected file download exploit attempt is seen. Additionally, the script tags data in http.log with the string "RFD" to make it easier to validate the activity. Both the list of CONTENT-TYPE header values and the RFD patterns can be edited by users after deploying the script via the redef command in a local.bro file.

Installation
---
* Clone the bro-scripts folder to the local Bro site folder
```
cd .../share/bro/site/
git clone --recursive https://github.com/CrowdStrike/NetworkDetection.git
```
* Add the script to the local.bro file 
```
@load bro-scripts/rfd/detect-rfd
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
* https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf
* https://www.trustwave.com/Resources/SpiderLabs-Blog/Reflected-File-Download---A-New-Web-Attack-Vector/
