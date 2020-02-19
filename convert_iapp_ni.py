import requests
import json
import sys
import argparse
import getpass
import time
import logging

requests.packages.urllib3.disable_warnings()

# Setup logging to send messages to console and convert.log file
log = logging.getLogger(__file__)
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler())
log.addHandler(logging.FileHandler('./convert.log'))

SUPPORTED_TEMPLATES = [
    'A-Travelers-iapp-template-v3',
    'A-Travelers-iapp-template-v2-8-2',
    'A-Travelers-iapp-template-v2-8-1',
    'A-Travelers-iapp-template-v2-8'
]

BIGIP_URL_BASE = ""
# REST resource for BIG-IP that all API requests will use
bigip = requests.session()
bigip.verify = False
bigip.headers.update({'Content-Type' : 'application/json'})

def convert(conf):
    #
    # INITILAZATION 
    #
    iappName = conf['name']
    profiles = []
    policies = []
    irulelist = []
    persprof = None
    snatpool = None
    securitylogprofile = None    
    secvipport = 0
    defaultpool = None

    ###############################################################################################
    #
    # Delete the existing iApp
    #
    ###############################################################################################
    log.info('\t\tDelete iApp: %s' % iappName)
    bigip.delete('%s/cloud/services/iapp/%s' % (BIGIP_URL_BASE, iappName))
    
    #
    # VIP and VIP Ports:
    #

    ###############################################################################################
    #
    # Set the port to 443 if SSL, otherwise set the port to what was specified
    #
    # Input: conf__secure_port=443 or conf__port=80
    # Output: vipport=80 or 443
    #
    ################################################################################################
    if conf['vars']['conf__isssl'] == '1':
        vipport = conf['vars']['conf__secure_port']
    else:
        vipport = conf['vars']['conf__port']
    
    # if using a well known secure vip port, record this for decisions on ssl passthrough later on
    if vipport == '443' or vipport == '8443':
        secvipport = 1
    
    
    
    ###############################################################################################
    #
    # Put the native vip port, and any additional vip ports (if any were specified) into a list
    #
    # Input: vipport=443 conf__multvipport=(8443, 9443)
    # Output: altvipport=(443, 8443, 9443)
    #
    ###############################################################################################
    altvipport = [ vipport ]

    if conf['vars']['conf__multvipport'] == '1':
        for item in conf['tables']['conf__multvipporttbl']['rows']:
            altvipport.append(item[0])


    ###############################################################################################
    #
    # Establish the variable for monitors by taking the monitor and any additional monitors
    #
    # Input:
    # Output: monitors { http https tcp-51500 }
    #
    ###############################################################################################
    monlist = []
    monlist.append(conf['vars']['conf__monitor'])
    if conf['vars']['conf__multmonitor'] == '1':
        for item in conf['tables']['conf__multmonitortbl']['rows']:
            monlist.append(item[0])

    #
    # SSL:
    #

    ###############################################################################################
    #
    # If SSL is enabled, create the LTM SSL profile for this iApp.
    # The key file name is derived from the cert file name. Assumed to the same as the cert file, but with a .key extension
    # Create a port 80 redirect profile if applicable
    #
    # Input: conf__cert=claimportal.travelers.com.crt
    # Output: LTM SSL profile objects: claimportal_ssl, claimportal_cert
    #         LTM redir VIP object: claimportal_redir_vip_80
    #         sslprofile=claimportal_ssl or "" $sslprofile is used later in the script for the final "create ltm vip" logic
    #
    # Command:
    # tmsh create ltm profile client-ssl claimportal_ssl { defaults-from trav-clientssl_prof cert-key-chain replace-all-with { claimportal_cert { cert claimportal.travelers.com.crt key claimportal.travelres.com.key } } }
    # tmsh create ltm profile client-ssl claimportal_ssl { defaults-from trav-clientssl_prof cert-key-chain replace-all-with { claimportal_cert { cert claimportal.travelers.com.crt key claimportal.travelres.com.key chain intermediate-veri-entr.crt } } }
    # tmsh create ltm virtual claimportal_redir_vip_80 destination 170.202.242.100:80 profiles replace-all-with { http tcp } rules { _sys_https_redirect }
    #
    ###############################################################################################
    
    
    # Create an SSL profile only if the user selected it AND provided a cert
    
    if conf['vars']['conf__isssl'] == '1' and conf['vars']['conf__cert'] != 'none':
        sslprofile = iappName + '_ssl'
        crtname = conf['vars']['conf__cert']
        keyname = str(crtname).replace('.crt', '.key')

        clientSSLProps = {
            'name': sslprofile,
            'certKeyChain': [{
                'name': iappName + '_cert',
                'cert': crtname,
                'key': keyname,
                'chain': conf['vars']['conf__chain']
            }],
            'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
        }
        if 'conf__basesslprof' in conf['vars'].keys():
            clientSSLProps['defaultsFrom'] = conf['vars']['conf__basesslprof']

        log.info('\t\tCreate clientSSL Profile: %s' % sslprofile)
        bigip.post('%s/ltm/profile/client-ssl/' % (BIGIP_URL_BASE), data=json.dumps(clientSSLProps))
        
        # Add clientSSL profile to profile list 
        profiles.append({'name': sslprofile, 'context': 'clientside' })

        
        if 'conf__redir80' in conf['vars'].keys() and conf['vars']['conf__redir80'] == '1':
            redirVipProps = {
                'name': iappName + '_redir_vip_80',
                'destination': conf['vars']['conf__addr'] + ':80',
                'profiles': [ 
                    {'name': '/Common/http'}, 
                    {'name': '/Common/tcp'}
                ],
                'rules': ['/Common/_sys_https_redirect'],
                'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
            }
            log.info('\t\tCreate redirect vip: %s ' % redirVipProps['name'])
            bigip.post('%s/ltm/virtual/' % (BIGIP_URL_BASE), data=json.dumps(redirVipProps))


    #
    # LB METHOD: Select appropriate method
    #

    ###############################################################################################
    #
    # Capture the load balance method
    #
    # Input: conf__lbmethod=round-robin, least-connections-node, least-sessions
    # Output: lbmethod=round-robin
    #         $lbmethod is used later in the script for the final "create ltm vip" logic
    #				  See all lbmethods with: "tmsh create ltm pool junk members replace-all-with  { 10.24.2.2:80 } load-balancing-mode ?"
    #
    ###############################################################################################
    lbmethod = conf['vars']['conf__lbmethod']

    #
    # PERSISTENCE:
    #

    ###############################################################################################
    #
    # Create persistence profile for this iApp if selected for this iApp
    #
    # Input: 	conf__persistence (none or any options from Local Traffic -> Profiles -> Persistence)
    # Output: persprof="persist replace-all-with { <predefined persistence profile> }"  OR
    #					persprof="persist none"
    #         persprof is used later in the script for the final "create ltm vip" logic to be used
    #
    ###############################################################################################
    if conf['vars']['conf__persistence'] != '' and conf['vars']['conf__persistence'] != 'none':
        persprof = conf['vars']['conf__persistence'] 

    #
    # SOURCE NAT: If SNAT was selected (1-armed config or Port Exhaustion), then enable)
    #

    ###############################################################################################
    #
    # Capture the SNAT setting
    #
    # Input: conf__snat
    # Output: snatpool=source-address-translation { type automap }
    #         $snatpool is used later in the script for the final "create ltm vip" logic
    #
    ###############################################################################################
    if conf['vars']['conf__snat'] == '1':
        snatpool = 'automap'

    #
    # IRULES: If irule(s) were selected, the build the irules variable to be applied to the iApp
    #

    ###############################################################################################
    #
    # Capture the iRules selected and put them in a list to be used when building the iApp
    #
    # Input: conf__addirule
    #        multiruletbl
    # Output: $irules=<list of selected irules>
    #         $irules is used later in the script for the final "create ltm vip" logic
    #
    ###############################################################################################
    if conf['vars']['conf__addirule'] == '1' and conf['tables']['conf__multiruletbl'] != {}:
        for item in conf['tables']['conf__multiruletbl']['rows']:
            irulelist.append(item[0])

    #
    # TCP PROFILE: By default assume that clients are local, if they are remote, use the wan-optimzed tcp profile
    #

    ###############################################################################################
    #
    # Capture client tcp profile settings (advanced). tcpprofiles inistialized to client-=wan, server=lan
    # If client and server tcp profile are both lan, then use "conext all" setting (othwise iApp won't work)
    #
    # Default: client is wan optimized, server is lan optimized
    #
    # Input: $tcpserverprof $tcpclientprof
    # Output: tcpprofiles=tcp-lan-optimized \{ context serverside \} tcp-wan-optimized \{ context clientside \} or
    #         $tcpserverprof \{ context all \}
    #         $tcpprofiles is used later in the script for the final "create ltm vip" logic
    #
    ###############################################################################################
    if conf['vars']['advanced__tcpclientprof'] == conf['vars']['advanced__tcpserverprof']:
        profiles.append({ 'name': conf['vars']['advanced__tcpclientprof'], 'context': 'all' })
    else:
        profiles.append({ 'name': conf['vars']['advanced__tcpclientprof'], 'context': 'clientside' })
        profiles.append({ 'name': conf['vars']['advanced__tcpserverprof'], 'context': 'serverside' })

    #
    # LAYER 7 APP CONFIGURATION
    #

    ###############################################################################################
    #
    # Input: conf__l7type
    # Output: Layer7 policy
    #
    ###############################################################################################
    if conf['vars']['conf__l7app'] == '1':

        #################################################
        # Create pools based on the pool__members table
        #################################################
        poollist = {}
        poolNameIndex = conf['tables']['pool__members']['columns'].index('l7pool')
        for item in conf['tables']['pool__members']['rows']:
            # Extract pool name from pool_members table record.  The index varies based on template
            poolName = item[poolNameIndex]

            # Initialize pool settings on first pool member reference to pool
            if poolName not in poollist.keys():
                poollist[poolName] = {
                    'name': poolName,
                    'monitor': " and ".join(monlist),
                    'loadBalancingMode': lbmethod,
                    'slow-ramp-time': 300,
                    'members': [ str(item[0]) + ':' + str(item[1]) ],
                    'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
                }
                if conf['vars']['conf__svrpriority'] == '1':
                    poollist[poolName]['minActiveMembers'] = 1
      
            # pool is already initialized so just append this pool member to 'members' list
            else: 
                poollist[poolName]['members'].append(str(item[0]) + ':' + str(item[1]))

        # Execute REST API call to create pools
        for pool in poollist.values():
            log.info('\t\tCreate Pool: %s ' % pool['name'])
            bigip.post('%s/ltm/pool/' % (BIGIP_URL_BASE), data=json.dumps(pool))



        #######################################################
        # Create policies based on the conf__l7switching table
        #######################################################

        # Build rule list for policy 
        ordinal = 1
        rules = []
        for item in conf['tables']['conf__l7switching']['rows']:
            ruleProps = {
                'name': str(item[0]).replace('/', '_'), 
                'ordinal': ordinal, 
                'actions': [{
                    'name': '0',
                    'forward': True,
                    'pool': item[1],
                    'request': True,
                    'select': True
                }],
                'conditions': [{
                    'name': '0',
                    'request': True,
                    'startsWith': True,
                    'values': [ item[0] ]
                }]
            }

            # determine the selector to be used in the policy rule properties condition section
            if conf['vars']['conf__l7type'] == "http-uri":
                ruleProps['conditions'][0]['path'] = True
                ruleProps['conditions'][0]['httpUri'] = True
            elif conf['vars']['conf__l7type'] == "http-host":
                ruleProps['conditions'][0]['host'] = True
                ruleProps['conditions'][0]['httpHost'] = True
            
            rules.append(ruleProps)
            ordinal += 1

        # The following default pool logic must always follow the URI loop above becuase the ord increment puts the default pool as the last entry in the later7 policy
        if conf['vars']['conf__defaultl7rule'] == 'Pool':
            ruleProps = {
                'name': 'catch-all-to-default-pool', 
                'ordinal': ordinal, 
                'actions': [ {
                    'name': '0',
                    'forward': True,
                    'pool': conf['vars']['conf__defaultl7pool'],
                    'request': True,
                    'select': True
                }]
            }
            rules.append(ruleProps)

        # Create the L7 http policy
        policyProps = {
            'name': iappName + '_l7policy',
            'controls': ['forwarding'],
            'requires': ['http'],
            'strategy': '/Common/first-match',
            'status': 'legacy',
            'legacy': True,
            'rules': rules,
            'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
        }
        log.info('\t\tCreate Policy: %s ' % policyProps['name'])
        bigip.post('%s/ltm/policy/' % (BIGIP_URL_BASE), data=json.dumps(policyProps))
        
        policies.append({'name': '/Common/' + policyProps['name']})

    
        # If the L7 default rule is "Pool" then set the default pool specified
        if conf['vars']['conf__defaultl7rule'] == 'Pool':
            defaultpool = conf['vars']['conf__defaultl7pool'] 

    #
    # POOL CREATION FOR NON-LAYER7 APPS
    #

    ###############################################################################################
    #
    # If this is not a layer7 app, then go through the pool__members, build the pmem variable to
    # include the server ip, port, server status, and priority-group.  Then issue the iapp command
    # to build the pool.
    #
    # Input: pool__members, $app, conf__monitor, $lbmethod
    # Output: tmsh create ltm pool claimportal members add { 1.1.1.1:80 { session user-disabled priority-group 1 } 2.2.2.2:80 {session user-enabled priority-group 2 } monitor http load-balancing-mode round-robin }
    #
    ###############################################################################################
    if conf['vars']['conf__l7app'] == '0':
        defaultpool = iappName + '_pool'
        members = []
        for item in conf['tables']['pool__members']['rows']:
            mem = {
                'name': str(item[0]) + ':' + str(item[1]),
                'address': item[0]
            }
            # Template v2-8 does not include priority group so we need to check before adding
            if item.__len__() > 2:
                mem['priorityGroup'] = item[2]

            members.append(mem)

        poolProps = {
            'name': iappName + '_pool',
            'monitor': " and ".join(monlist),
            'loadBalancingMode': lbmethod,
            'slow-ramp-time': 300,
            'members': members,
            'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
        }
        if conf['vars']['conf__svrpriority'] == '1':
            poolProps['minActiveMembers'] = 1
        
        log.info('\t\tCreate Pool: %s ' % poolProps['name'])
        bigip.post('%s/ltm/pool/' % (BIGIP_URL_BASE), data=json.dumps(poolProps))


    #
    # ASM APP CONFIGURATION
    #

    ###############################################################################################
    #
    # Input: conf__asmpol, conf__logprof
    # Output: websec, securitylogprofile
    #
    ###############################################################################################
    if 'conf__asmapp' in conf['vars'].keys() and 'conf__asmpol' in conf['vars'].keys() and conf['vars']['conf__asmapp'] == '1':
        policies.append({ 'name': conf['vars']['conf__asmpol'] })
        profiles.append({ 'name': 'websecurity', 'context': 'all' })

        if 'conf__logprof' in conf['vars'].keys():
            securitylogprofile = conf['vars']['conf__logprof']
    
    if 'conf__dosapp' in conf['vars'].keys() and 'conf__dosprof' in conf['vars'].keys() and conf['vars']['conf__dosapp'] == '1':
        profiles.append({ 'name': conf['vars']['conf__dosprof'] })
      

    #
    # ICAP APP CONFIGURATION
    #

    ###############################################################################################
    #
    # Input: conf__icap
    # Output: reqadaptprofile
    #
    ###############################################################################################
    if 'conf__icap' in conf['vars'].keys() and conf['vars']['conf__icap'] == '1':
        profiles.append({ 'name': conf['vars']['conf__reqadaptprof'] })


    #
    # HTTP PROFILE
    #

    ###############################################################################################
    #
    # Assign appropriate http profile setting
    #
    # Input:  advanced__httpprofdis, advanced__httpprof
    # Output: LTM HTTP Profile Objects
    #         $httpprof is used later in the script for the final "create ltm vip" logic
    #
    ###############################################################################################
    # The A-Travelers-iapp-template-v2-8-1 template handles HTTP profiles differently
    if conf['template'] == 'A-Travelers-iapp-template-v2-8-1' or \
       conf['template'] == 'A-Travelers-iapp-template-v2-8':
        if conf['vars']['advanced__httpprofdis'] == '1':
            pass
        elif conf['vars']['conf__xff'] != '1':
            profiles.append({ 'name': 'trav-http_prof' })
        elif conf['vars']['conf__l7app'] == '1':
            profiles.append({ 'name': 'trav-http-xff_prof' })
        elif 'cookie' in str(persprof):
            profiles.append({ 'name': 'trav-http-xff_prof' })
        elif conf['vars']['conf__isssl'] == '0' and secvipport:
            pass
        elif conf['vars']['conf__isssl'] == '1':
            profiles.append({ 'name': 'trav-http-xff_prof' })
        elif conf['vars']['conf__addirule'] == '1':
            profiles.append({ 'name': 'trav-http-xff_prof' })
        elif conf['vars']['advanced__oneconn'] != 'None':
            profiles.append({ 'name': 'trav-http-xff_prof' })
        else:
            pass

    # The rest of the templates use this logic
    else:
        if conf['vars']['advanced__httpprofdis'] == '1':
            pass
        else:
            profiles.append({ 'name': conf['vars']['advanced__httpprof'] })

    #
    # ONECONNECT: ADVANCED
    #

    ###############################################################################################
    #
    # Capture the oneconnect setting. Default is enabled (multiplex client sessions to server)
    # For SSL apps, 32bit mask oneconnect is used.
    # For other situations you may elect to turn oneconnect off all together
    #
    # Input: advanced__oneconn, conf__isssl
    # Output: $oneconnect
    # $oneconnect is used later in the script for the final "create ltm vip" logic
    #
    ###############################################################################################

    # Determine the proper oneconnect setting. The top condition allows for an always override.
    # If SSL pass through, (!isssl and vipport 443), then singleplex
    if conf['vars']['advanced__oneconn'] == 'None':
        pass
    elif conf['vars']['conf__isssl'] == '0' and secvipport:
        profiles.append({ 'name': 'trav-oneconnect-singleplex' })
    elif conf['vars']['conf__isssl']:
        profiles.append({ 'name': 'trav-oneconnect-singleplex' })
    else:
        profiles.append({ 'name': conf['vars']['advanced__oneconn'] })

    #
    # CREATE THE VIP
    #

    ###############################################################################################
    #
    # If this is not a layer7 app, then create the VIP without a Layer7 policy
    # If this is a layer7 app, then create the VIP with a Layer7 policy
    #
    # Input: Lots of varaibles from the above code
    # Output: iapp::conf create ltm virtual ${app}_redir_vip_80 destination [iapp::destination conf__addr 80] profiles replace-all-with \{ http tcp \} rules \{ _sys_https_redirect \}
    # The tmsh commands below. See /var/tmp/scriptd.out for example after building iApp
    #
    ###############################################################################################
    
    # Initialize vip base object with common configuration attributes
    vipProps = {
        'mask': '255.255.255.255',
	    'source': '0.0.0.0/0',
        'metadata': [ { 'name': 'app', 'value': iappName, 'persist': True } ]
    }
    
    # Profiles - including TCP, HTTP, OneConnect, requestAdapt (ICAP), DDoS, Websecurity
    if profiles.__len__() > 0:
        vipProps['profiles'] = profiles
    
    # Polices - including ASM and Layer7 (Host and URL pool forwarding)
    if policies.__len__() > 0:
        vipProps['policies'] = policies

    # iRules
    if irulelist.__len__() > 0:
        vipProps['rules'] = irulelist
    
    # Persistence
    if persprof:
        vipProps['persist'] = persprof

    # Logging Profile
    if securitylogprofile:
        vipProps['securityLogProfiles'] = [ securitylogprofile ]

    # SNAT
    if snatpool:
        vipProps['sourceAddressTranslation'] = { 'type': 'automap' }

    # Default Pool
    if defaultpool:
        vipProps['pool'] = defaultpool

    # Create a Vip for each port included in the altvipport list
    for vport in altvipport:
        vipProps['name'] = iappName + '_vip_' + str(vport)
        vipProps['destination'] = conf['vars']['conf__addr'] + ':' + str(vport)

        log.info('\t\tCreate vip: %s ' % vipProps['name'])
        bigip.post('%s/ltm/virtual/' % (BIGIP_URL_BASE), data=json.dumps(vipProps))

        
if __name__ == '__main__':
    # Get command line arguments 
    parser = argparse.ArgumentParser(description='F5 Big-IP iApp conversion utility')
    parser.add_argument('--host', help='BIG-IP IP or Hostname', required=True)
    parser.add_argument('--username', help='BIG-IP Username', required=True)
    parser.add_argument('--password', help='BIG-IP Password')
    parser.add_argument('--iapp', help='iApp Name. When specified this will be the only converted iApp')
    parser.add_argument('--from-file', help='Source file containing an iApp name per line')
    parser.add_argument('--all', action='store_true', help='Convert all iApps')
    args = vars(parser.parse_args())

    # Setup Password
    if args['password'] != None:
        password = args['password']
    else:
        print("User: %s, enter your password: " % args['username'])
        password = getpass.getpass()

    # Update the bigip url global variable
    BIGIP_URL_BASE = 'https://%s/mgmt/tm' % args['host']

    # Configure default API authentication
    bigip.auth = (args['username'], password)

    # Prepare list of iApps to be converted
    iAppConvertList = []
    if args['iapp']:
        # Only convert this iApp
        iAppConvertList.append(args['iapp'])
    elif args['from_file']:
        try:
            f = open(args['from_file'])
            for line in f:
                iAppConvertList.append(str(line).replace(' ', '').rstrip('\r\n'))
            f.close()
        except:
            log.info('Error encountered reading file:  %s' % args['from_file'])
    elif args['all']:
        # Get all iApps
        iAppConvertList = bigip.get('%s/cloud/services/iapp/' % BIGIP_URL_BASE).json()['items']
    else:
        log.info('Nothing to convert....exiting')
        sys.exit()

    # Verify that we can get a list of iApps from Big-IP
    #  Since this is the first API attempt we will wrap the call in a try/except statement and
    #  test for sucessful authentication
    try:
        log.info('Getting list of iApps from Big-IP host: %s' % args['host'])
        response = bigip.get('%s/cloud/services/iapp/' % (BIGIP_URL_BASE))
        if response.status_code != 200:
            log.info(' API Error: %s' % response.reason)
            sys.exit(1)
        iAppHostList = response.json()['items']
    except:
        log.info(' Communication failure: Unable to communication with Big-IP')
        sys.exit(1)

    # Begin conversion process 
    failedList = []
    successList = []
    skippedList = []
    for iAppName in iAppConvertList:
        log.info('\nStarting conversion for iApp: %s' % iAppName)

        # Get iApp definition 
        log.info('\tGetting iApp configuration')
        response = bigip.get('%s/cloud/services/iapp/%s' % (BIGIP_URL_BASE, iAppName))
        if response.status_code == 200:
            iApp = response.json()
        else:
            log.info('\tiApp not found: %s....skipping' % iAppName)
            skippedList.append({ 'name': iAppName, 'reason': 'not found' })
            continue

        # Verify template is supported
        if iApp['template'] not in SUPPORTED_TEMPLATES:
            log.info('\tUnsupported template: %s....skipping' % iApp['template'])
            skippedList.append({ 'name': iAppName, 'reason': 'unsupported template' })
            continue
        
        # Create API transaction and update the bigip API object with X-F5-REST-Coordination-Id header
        transId = bigip.post('%s/transaction' % (BIGIP_URL_BASE), data=json.dumps({})).json()['transId']
        log.info('\tSetting up API transaction for conversion. txId: %s' % transId)
        bigip.headers.update({'X-F5-REST-Coordination-Id' : str(transId)})
        
        # Populate API transaction with the required commands.  All API commands entered by the convert
        #  subroutine will entered into the transaction and only executed at transaction run time
        try:
            convert(iApp)
        except Exception as e:
            log.info('\tEncounter exception during migration: %s....skipping' % str(e))
            skippedList.append({ 'name': iAppName, 'reason': 'encountered exception: %s' % str(e) })
            del bigip.headers['X-F5-REST-Coordination-Id']
            continue


        # Remove Transaction ID from bigip API object X-F5-REST-Coordination-Id header
        del bigip.headers['X-F5-REST-Coordination-Id']


        # Start the API transaction and get the result
        bigip.patch('https://10.1.1.131/mgmt/tm/transaction/%i' % transId, data=json.dumps({'state': 'VALIDATING'}))
        transResult = bigip.get('https://10.1.1.131/mgmt/tm/transaction/%i' % transId).json()
        if transResult['state'] == 'FAILED':
            log.info('\tConverting iApp...Failed')
            failedList.append({'name': iAppName, 'reason': transResult['failureReason']})
        else:
            log.info('\tConverting iApp...Success')
            successList.append({'name': iAppName})

    log.info('\n\n#####################################################')
    log.info('#                     SUMMARY                       #')
    log.info('#####################################################')

    log.info('\nSUCCESSFUL CONVERSIONS: %i' % successList.__len__())
    for ic in successList:
        log.info('%s' % (ic['name']))

    log.info('\nSKIPPED CONVERSIONS: %i' % skippedList.__len__())
    for ic in skippedList:
        log.info('%s - Reason: %s' % (ic['name'], ic['reason'])) 
    
    log.info('\nFAILED CONVERSIONS: %i' % failedList.__len__())
    for ic in failedList:
        log.info('%s - Reason: %s' % (ic['name'], ic['reason']))