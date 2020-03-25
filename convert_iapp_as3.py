import requests
import json
import sys
import argparse
import getpass
import time
import logging
import time

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

BIGIP_URL_BASE = ''
# REST resource for BIG-IP that all API requests will use
bigip = requests.session()
bigip.verify = False
bigip.headers.update({'Content-Type' : 'application/json'})

def do_rest(method, path, data=None):
    try:
        response = None
        resData = {}
        if method == 'get':
            response = bigip.get(BIGIP_URL_BASE + path)
            resData = response.json() 
        elif method == 'post':
            response = bigip.post(BIGIP_URL_BASE + path, data=json.dumps(data)) 
            resData = response.json() 
        elif method == 'delete':
            response = bigip.delete(BIGIP_URL_BASE + path) 
        else:
            # Unsupported method return none
            return {'success': False, 'data': {}, 'error': 'unsupported method'}
        
        if response.status_code == 200 or response.status_code == 202:
            return {'success': True, 'data': resData, 'error': ''}
        else:
            return {'success': False, 'data': {}, 'error': response.reason}
    except Exception as e:
        return {'success': False, 'data': {}, 'error': str(e)}
        

def prepend_common(name):
    if str(name).startswith('/Common/'):
        return name
    else:
        return '/Common/' + name

def convert(conf):
    #
    # INITILAZATION 
    #
    #iappName = str(conf['name']).replace('-', '_')
    iappName = str(conf['name'])
    profiles = []
    l7policy = None
    irulelist = []
    snat = None
    secvipport = 0
    createRedirectVip = False
    defaultpool = None
    persprof = None

    as3 = {
        'class': 'ADC',
        'schemaVersion': '3.2.0',
        'id': iappName,
        'label': '',
        'remark': 'Travelers AS3 Declaration',
        iappName: {
            'class': 'Tenant',
            'app': {
                'class': 'Application',
                'template': 'http'
            }
        }
    }
   
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
    if conf['vars']['conf__isssl'] == '1' and not (conf['vars']['conf__cert'] == 'none' or conf['vars']['conf__cert'] == 'TBD'):
        vipport = conf['vars']['conf__secure_port']
        secvipport = 1
    else:
        vipport = conf['vars']['conf__port']
    
    # if using a well known secure vip port, record this for decisions on ssl passthrough later on
    if (vipport == '443' or vipport == '8443') and not (conf['vars']['conf__cert'] == 'none' or conf['vars']['conf__cert'] == 'TBD'):
        secvipport = 1

    if secvipport:
        as3[iappName]['app']['template'] = 'https'

    
    
    
    
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
    if conf['vars']['conf__monitor'] != 'none':
        monlist.append({'bigip': prepend_common(conf['vars']['conf__monitor'])})
        if conf['vars']['conf__multmonitor'] == '1':
            for item in conf['tables']['conf__multmonitortbl']['rows']:
                monlist.append({'bigip': prepend_common(item[0])})

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
    
    if secvipport and conf['vars']['conf__cert'] != 'none':
        sslprofile = iappName + '_ssl'
        crtname = conf['vars']['conf__cert']
        keyname = str(crtname).replace('.crt', '.key')

        # Configure Certificate Class
        as3[iappName]['app'][iappName + '_cert'] = {
            'class': 'Certificate',
            'certificate': { 'bigip': prepend_common(crtname) },
            'privateKey': { 'bigip': prepend_common(keyname) }
        }

        # Set optional chain CA value
        if 'conf__chain' in conf['vars'].keys() and conf['vars']['conf__chain'] != 'none':
            as3[iappName]['app'][iappName + '_cert']['chainCA'] = { 'bigip': prepend_common(conf['vars']['conf__chain']) }

        # Configure TLS Server Class
        as3[iappName]['app'][iappName + '_ssl'] = {
            'class': 'TLS_Server',
            'certificates': [
                { 'certificate': iappName + '_cert' }
            ]
        }

        # Handle optional settings that are configured through the base SSL profile.  As of AS3 version
        # 3.17.1 there is no parent profile option so we will adjust this clientSSL profile with the custom
        # settings.  NOTE: AS3 does not support modifying the 'Options' attribute.  This will need to be added
        if 'conf__basesslprof' in conf['vars'].keys():
            as3[iappName]['app'][iappName + '_ssl']['ciphers'] = 'ECDHE:@STRENGTH:DEFAULT:!3DES:!DHE'

        # Add TLS Class to profile list 
        profiles.append({ 
            'key': 'serverTLS', 
            'value': sslprofile 
            })

        
        if 'conf__redir80' in conf['vars'].keys() and conf['vars']['conf__redir80'] == '1':
            createRedirectVip = True

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
        profiles.append({
            'key': 'persistenceMethods',
            'value': [{ 'bigip': prepend_common(conf['vars']['conf__persistence']) }]
        })

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
        snat = 'auto'

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
            irulelist.append({ 'bigip': prepend_common(item[0]) })

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
    profiles.append({ 
        'key': 'profileTCP', 
        'value': { 'bigip': prepend_common(conf['vars']['advanced__tcpclientprof']) }
    })

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
        # Create AS3 pool classes based on the pool__members table
        #################################################
        poollist = {}
        poolNameIndex = conf['tables']['pool__members']['columns'].index('l7pool')
        addrIndex = conf['tables']['pool__members']['columns'].index('addr')
        portIndex = conf['tables']['pool__members']['columns'].index('port')

        # The items below will only appear in certain templates
        priorityIndex = -1
        try:
            priorityIndex = conf['tables']['pool__members']['columns'].index('priority')
        except:
            pass

        statusIndex = -1
        try:
            statusIndex = conf['tables']['pool__members']['columns'].index('serverstatus')
        except:
            pass

        for item in conf['tables']['pool__members']['rows']:
            # Extract pool name from pool_members table record.  The index varies based on template
            #poolName = str(item[poolNameIndex]).replace('-', '_')
            poolName = str(item[poolNameIndex])
            addr = item[addrIndex]
            port = item[portIndex]

            # Initialize pool settings on first pool member reference to pool
            if poolName not in poollist.keys():

                as3[iappName]['app'][poolName] = {
                    'class': 'Pool',
                    'loadBalancingMode': lbmethod,
                    'slowRampTime': 300,
                    'monitors': monlist,
                    'members': []
                }
                if conf['vars']['conf__svrpriority'] == '1':
                    as3[iappName]['app'][poolName]['minimumMembersActive'] = 1

                
      
            # pool is already initialized so append this pool member to 'members' list
            member = {
                'servicePort': int(port),
                'serverAddresses': [ addr ]
            }
            # Check for member priority
            if priorityIndex != -1:
                member['priorityGroup'] = int(item[priorityIndex])

            # Check for member state. 
            if statusIndex  != -1:
                if item[statusIndex] == '0':
                    member['enable'] = False
                else:
                    member['enable'] = True
            as3[iappName]['app'][poolName]['members'].append(member)

    
        #######################################################
        # Create policies based on the conf__l7switching table
        #######################################################

        # Configure Endpoint_Policy AS3 Class 
        #l7policy = str(iappName + '_l7policy').replace('-', '_')
        l7policy = str(iappName + '_l7policy')

        as3[iappName]['app'][l7policy] = {
            'class': 'Endpoint_Policy',
            'strategy': 'first-match',
            'rules': []
        }

        # Populate Rules based on conf__l7switching table
        for item in conf['tables']['conf__l7switching']['rows']:
            rule = {
                #'name': 'rule' + str(item[0]).replace('/', '_').replace('-', '_'),
                'name': 'rule' + str(item[0]).replace('/', '_'),
                "actions": [
                    {
                        "type": "forward",
                        "event": "request",
                        "select": {
                            "pool": {
                                #"use": str(item[1]).replace('-', '_')
                                "use": str(item[1])
                            }
                        }
                    }
                ]
            }

            if conf['vars']['conf__l7type'] == 'http-uri':
                rule['conditions'] = [ 
                    { 
                        'type': 'httpUri',
                        'path': {
                            'operand': 'starts-with',
                            'values': [ item[0] ]
                        }
                    }
                ]
            elif conf['vars']['conf__l7type'] == 'http-host':
                rule['conditions'] = [ 
                    { 
                        'type': 'httpHost',
                        'path': {
                            'operand': 'starts-with',
                            'values': [ item[0] ]
                        }
                    }
                ]
            
            # Append to rule list
            as3[iappName]['app'][l7policy]['rules'].append(rule)


        # The following default pool logic must always follow the URI loop above becuase the ord increment puts the default pool as the last entry in the later7 policy
        if conf['vars']['conf__defaultl7rule'] == 'Pool':
            as3[iappName]['app'][l7policy]['rules'].append(
                {
                    'name': 'catch_all_to_default_pool',
                    'conditions': [],
                    'actions': [
                        {
                            'type': 'forward',
                            'event': 'request',
                            'select': {
                                'pool': {
                                    #'use': str(conf['vars']['conf__defaultl7pool']).replace('-', '_')
                                    'use': str(conf['vars']['conf__defaultl7pool'])
                                }
                            }
                        }
                    ]   
                }
            )
    
        # If the L7 default rule is "Pool" then set the default pool specified
        if conf['vars']['conf__defaultl7rule'] == 'Pool':
            #defaultpool = str(conf['vars']['conf__defaultl7pool']).replace('-', '_')
            defaultpool = str(conf['vars']['conf__defaultl7pool'])

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
        as3[iappName]['app'][defaultpool] = {
            'class': 'Pool',
            'loadBalancingMode': lbmethod,
            'slowRampTime': 300,
            'monitors': monlist,
            'members': []
        }
        if conf['vars']['conf__svrpriority'] == '1':
            as3[iappName]['app'][defaultpool]['minimumMembersActive'] = 1

        # Process pool members
        addrIndex = conf['tables']['pool__members']['columns'].index('addr')
        portIndex = conf['tables']['pool__members']['columns'].index('port')

        # The items below will only appear in certain templates
        priorityIndex = -1
        try:
            priorityIndex = conf['tables']['pool__members']['columns'].index('priority')
        except:
            pass

        statusIndex = -1
        try:
            statusIndex = conf['tables']['pool__members']['columns'].index('serverstatus')
        except:
            pass

        for item in conf['tables']['pool__members']['rows']:
            addr = item[addrIndex]
            port = item[portIndex]

            # pool is already initialized so append this pool member to 'members' list
            member = {
                'servicePort': int(port),
                'serverAddresses': [ addr ]
            }
            # Check for member priority
            if priorityIndex != -1:
                member['priorityGroup'] = int(item[priorityIndex])

            # Check for member state. 
            if statusIndex  != -1:
                if item[statusIndex] == '0':
                    member['enable'] = False
                else:
                    member['enable'] = True
            as3[iappName]['app'][defaultpool]['members'].append(member)

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
        profiles.append({ 
            'key': 'policyWAF',
            'value': { 'bigip': prepend_common(conf['vars']['conf__asmpol']) }
        })

        if 'conf__logprof' in conf['vars'].keys():
            profiles.append({ 
                'key': 'securityLogProfiles',
                'value': [{ 'bigip': prepend_common(conf['vars']['conf__logprof'])  }]
            })

    
    if 'conf__dosapp' in conf['vars'].keys() and 'conf__dosprof' in conf['vars'].keys() and conf['vars']['conf__dosapp'] == '1':
        profiles.append({ 
            'key': 'profileDOS',
            'value': { 'bigip': prepend_common(conf['vars']['conf__dosprof']) }
        })
      

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
        profiles.append({ 
            'key': 'profileRequestAdapt',
            'value': { 'bigip': prepend_common(conf['vars']['conf__reqadaptprof']) }
        })


    ######### STOPPED HERE AND NEED TO ADD MONITORS TO THE POOLS ##################

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
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http_prof' }
            })
        elif conf['vars']['conf__l7app'] == '1':
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http-xff_prof' }
            })
        elif 'cookie' in str(persprof):
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http-xff_prof' }
            })
        elif conf['vars']['conf__isssl'] == '0' and secvipport:
            pass
        elif conf['vars']['conf__isssl'] == '1':
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http-xff_prof' }
            })
        elif conf['vars']['conf__addirule'] == '1':
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http-xff_prof' }
            })
        elif conf['vars']['advanced__oneconn'] != 'None':
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': '/Common/trav-http-xff_prof' }
            })
        else:
            pass

    # The rest of the templates use this logic
    else:
        if conf['vars']['advanced__httpprofdis'] == '1':
            pass
        else:
            profiles.append({ 
                'key': 'profileHTTP',
                'value': { 'bigip': prepend_common(conf['vars']['advanced__httpprof']) }
            })

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
        profiles.append({ 
            'key': 'profileMultiplex',
            'value': { 'bigip': '/Common/trav-oneconnect-singleplex' }
        })
    elif conf['vars']['conf__isssl']:
        profiles.append({ 
            'key': 'profileMultiplex',
            'value': { 'bigip': '/Common/trav-oneconnect-singleplex' }
        })
    else:
        profiles.append({ 
            'key': 'profileMultiplex',
            'value': { 'bigip': prepend_common(conf['vars']['advanced__oneconn']) }
        })

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

    # Configure Service Classes 
    servicePropsBase = {}

     # Choose class based on secvipport value
    if secvipport:
        servicePropsBase['class'] = 'Service_HTTPS'
    else:
        servicePropsBase['class'] = 'Service_HTTP'
    
    # Profiles
    for profile in profiles:
        servicePropsBase[profile['key']] = profile['value']

    # iRules
    if irulelist.__len__() > 0:
        servicePropsBase['iRules'] = irulelist

    # SNAT
    if snat:
        servicePropsBase['snat'] = snat

    # Policy
    if l7policy:
        servicePropsBase['policyEndpoint'] = l7policy

    # Default Pool
    if defaultpool:
        servicePropsBase['pool'] = defaultpool

    # Create a service class for each port included in the altvipport list
    counter = 1
    for vport in altvipport:

        # We must use the name 'serviceMain' for the first service in AS3
        if counter == 1:
            serviceName = 'serviceMain'
        else:
            serviceName = 'vip_' + str(vport)
        
        # Create a new dict instance for this service based on servicePropsBase
        as3[iappName]['app'][serviceName] = servicePropsBase.copy()

        # Set address and port
        as3[iappName]['app'][serviceName]['virtualPort'] = int(vport)
        as3[iappName]['app'][serviceName]['virtualAddresses'] = [ conf['vars']['conf__addr'] ]

        # Check if redirect virtual should be created.  Only on the first service
        if counter == 1 and createRedirectVip:
            as3[iappName]['app'][serviceName]['redirect80'] = True

        counter += 1

    log.info('\t\tPost AS3 Declaration for tenant: %s ' % iappName)

    as3TaskStart = time.time()
    res = do_rest('post', '/shared/appsvcs/declare?async=true', data=as3)
    if res['success']:
        taskId = res['data']['id']

        # Check for task completion 
        while True:
            taskRes= do_rest('get', '/shared/appsvcs/task/%s' % taskId)
            if taskRes['success']:
                taskData = taskRes['data']
                
                if taskData['results'][0]['code'] == 0:  # Task is in progress
                    time.sleep(1)
                elif taskData['results'][0]['code'] == 200:  # Task completed successfully
                    log.info("\t\t...success in %i secs" % int(time.time() - as3TaskStart)) 
                    return {'status': 'success', 'message': ''} 
                else:  # Assume task ended in error
                    msg = taskData['results'][0]['message'] 
                    if 'response' in taskData['results'][0].keys():
                        msg = '%s: %s' % (taskData['results'][0]['message'], taskData['results'][0]['response'])
                    
                    log.error("\t\t...failed with msg: %s" % msg)
                    return {'status': 'failed', 'message': msg}
            else:
                log.error("\t\t...failed checking AS3 task")
                return {'status': 'failed', 'message': taskRes['error']}
    else:
        log.error("\t\t...failed submitting AS3 task")
        return {'status': 'failed', 'message': taskRes['error']}   

    # We are done.  Return success
    return {'status': 'success', 'message': ''}
        
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
    BIGIP_URL_BASE = 'https://%s/mgmt' % args['host']

    # Configure default API authentication
    bigip.auth = (args['username'], password)

    # Test communication with Big-IP and make sure AS3 is installed
    res = do_rest('get', '/shared/appsvcs/info')
    if not res['success']:
        log.error('Unable to log into BigIP and verify AS3 is installed.  Error: %s' % res['error'])
        sys.exit(1)

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
        res = do_rest('get', '/tm/cloud/services/iapp/')
        if res['success']:
            iAppConvertList = res['data']['items']
        else:
            log.error('Failed to download iApp list from BigIP with message: %s' % res['error'])
            sys.exit(1)
    
    else:
        log.info('Nothing to convert....exiting')
        sys.exit()

    # Begin conversion process 
    starttime= time.time()
    failedList = []
    successList = []
    skippedList = []
    for iAppName in iAppConvertList:
        log.info('\nStarting conversion for iApp: %s' % iAppName)

        # Get iApp definition 
        log.info('\tGetting iApp configuration')
        res = do_rest('get', '/tm/cloud/services/iapp/%s' % iAppName)
        if res['success']:
            iApp = res['data']
        else:
            log.info('\tiApp not found: %s....skipping' % iAppName)
            skippedList.append({ 'name': iAppName, 'reason': 'not found' })
            continue

        # Verify template is supported
        if iApp['template'] not in SUPPORTED_TEMPLATES:
            log.info('\tUnsupported template: %s....skipping' % iApp['template'])
            skippedList.append({ 'name': iAppName, 'reason': 'unsupported template' })
            continue

        # Remove the existing iApp
        log.info('\t\tDelete iApp: %s' % iAppName)
        res = do_rest('delete', '/tm/cloud/services/iapp/%s' % (iAppName))
        if res['success']:
            log.info("\t\t...success")
        else:
            log.error("\t\t...failed.  Could not remove iApp")
            failedList.append({ 'name': iAppName, 'reason': 'Could not remove iApp'})
            continue
        
        # Attempt conversion
        result = convert(iApp)
        if result['status'] == 'failed':
            log.info('\tConverting iApp...Failed')
            
            msg = ''
            # Attempt to restore the original iApp
            log.error('\tAttempting to recover from error by redeploying the iApp: %s' % (iAppName))
            res = do_rest('post', '/tm/cloud/services/iapp/', data=iApp)
            if res['success']:
                log.error('\t...success')
            else:
                log.error('\t...RECOVERY FAILURE.  MANUAL INTERVENTION REQUIRED')
                msg = 'IAPP RECOVERY FAILURE.  MANUAL INTERVENTION REQUIRED: '
            msg = msg + result['message']
            failedList.append({ 'name': iAppName, 'reason': msg })
                
        else:
            log.info('\tConverting iApp...Success')
            successList.append({'name': iAppName})


    log.info('\n\n#####################################################')
    log.info('#                     SUMMARY                       #')
    log.info('#####################################################')

    log.info('\nRun Time: %i' % int(time.time() - starttime))
    
    log.info('\nSUCCESSFUL CONVERSIONS: %i' % successList.__len__())
    for ic in successList:
        log.info('%s' % (ic['name']))

    log.info('\nSKIPPED CONVERSIONS: %i' % skippedList.__len__())
    for ic in skippedList:
        log.info('%s - Reason: %s' % (ic['name'], ic['reason'])) 
    
    log.info('\nFAILED CONVERSIONS: %i' % failedList.__len__())
    for ic in failedList:
        log.info('%s - Reason: %s' % (ic['name'], ic['reason']))