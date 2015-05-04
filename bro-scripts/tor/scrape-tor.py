# Collect Tor server list from torstatus.blutmagie.de and convert it to a tab-delimited format
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com
# @jshlbrd

import os
import csv
import urllib
urllib.urlretrieve ("https://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv", "tor.csv")

infile = open('tor.csv','rb')
reader = csv.reader(infile)
outfile_name = 'bro-tor.txt'
outfile = open(outfile_name, 'wb')
outfile.write('#fields\t')
writer = csv.writer(outfile, delimiter='\t')

next(reader, None)
# extraneous header 'extra' included to stop an error I couldn't run down when Bro tries to read the file ...
writer.writerow(['tor_ip', 'router_name','country_code', 'bandwidth', 'uptime', 'host_name', 'router_port', 'directory_port', 'auth_flag', 'exit_flag', 'fast_flag', 'guard_flag', 'named_flag', 'stable_flag', 'running_flag', 'valid_flag', 'v2dir_flag', 'platform', 'hibernating_flag', 'bad_exit_flag', 'extra'])

# columns are re-ordered to allow easier indexing for Bro
for row in reader:
        writer.writerow([row[4],row[0],row[1],row[2],row[3],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12],row[13],row[14],row[15],row[16],row[17],row[18],row[19], '0'])

infile.close()
outfile.close()

os.remove('tor.csv')
