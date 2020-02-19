import requests
import json
import sys
import time
import argparse
import getpass

requests.packages.urllib3.disable_warnings()

# Get command line arguments 
parser = argparse.ArgumentParser(description='F5 Big-IP iApp conversion utility')
parser.add_argument('--host', help='BIG-IP IP or Hostname', required=True)
parser.add_argument('--username', help='BIG-IP Username', required=True)
parser.add_argument('--password', help='BIG-IP Password')
args = vars(parser.parse_args())

BIGIP_URL_BASE = 'https://%s/mgmt/tm' % args['host']
FILENAME = 'iapps_%s.txt' % str(args['host']).replace('.', '_')
# Setup Password
if args['password'] != None:
    password = args['password']
else:
    print("User: %s, enter your password: " % args['username'])
    password = getpass.getpass()

# REST resource for BIG-IP that all other requests will use
bigip = requests.session()
bigip.verify = False
bigip.headers.update({'Content-Type' : 'application/json'})
bigip.auth = (args['username'], password)

try:
    iApps = bigip.get('%s/cloud/services/iapp/' % BIGIP_URL_BASE).json()['items']
    with open(FILENAME , 'w') as f:
        for item in iApps:
            f.write("%s\n" % item)
except:
    print('Failed to download iApps from BigIP: %s.  Check creds and connectivity' % args['host'])