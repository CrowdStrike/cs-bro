# Rudimentary script to collect domains in the Alexa top 500
# This script can be run as often as needed to refresh the list of domains
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com

import requests
import bs4

# File containing Alexa top 500 domains
# This file name and path is referenced in the Bro script and can be modified
f = open('alexa_domains.txt','w')
f.write('#fields\talexa\n')

# Alexa's top 500 domains are spread across 20 pages
# To change the number of domains collected (top 50, top 250), modify the range
for num in range(0,20):
  site = "http://www.alexa.com/topsites/global;" + str(num)
  page = requests.get(site)
  soup = bs4.BeautifulSoup(page.text)

  for link in soup.find_all('a'):
    if 'siteinfo' in str(link):
      f.write((link.get('href')).split("/")[2] + "\n" )
