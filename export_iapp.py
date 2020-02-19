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
parser.add_argument('--iapp', help='iApp Name to be exported', required=True)
parser.add_argument('--password', help='BIG-IP Password')
args = vars(parser.parse_args())

BIGIP_URL_BASE = 'https://%s/mgmt/tm' % args['host']
FILENAME = 'iapp_%s.json' % (args['iapp'])

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
    response = bigip.get('%s/cloud/services/iapp/%s' % (BIGIP_URL_BASE, args['iapp']))
    if response.status_code == 200:
        with open(FILENAME, "w") as f:
            json.dump(response.json(), f, indent=4)
    else:
        print('Could not get iApp')
except:
    print('Communication failure with BigIP: %s' % args['host'])