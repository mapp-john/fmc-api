# Import Required Modules
import os
import re
import sys
import csv
import json
import socket
import random
import netaddr
import getpass
import requests
import traceback


#
#
#
# Define Password Function
def define_password():
    password = None
    while not password:
        password = getpass.getpass('Please Enter Password: ')
        passwordverify = getpass.getpass('Re-enter Password to Verify: ')
        if not password == passwordverify:
            print('Passwords Did Not Match Please Try Again')
            password = None
    return password

#
#
#
# Define Generate Access Token Function
def access_token(server,headers,username,password):
    auth_url = f'{server}/api/fmc_platform/v1/auth/generatetoken'
    try:
        # REST call with SSL verification turned off:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        print(r.status_code)
        auth_token = r.headers['X-auth-access-token']
        domains = json.loads(r.headers['DOMAINS'])
        if auth_token == None:
            print('auth_token not found. Exiting...')
            sys.exit()
    except Exception as err:
        print (f'Error in generating auth token --> {traceback.format_exc()}')
        print(r.headers)
        sys.exit()
    return auth_token,domains

#
#
# Get Device Details from Inventory List
# And Delete item from Inventory List
def get_device_details(ID,DeviceList):
    temp_dict = {}
    for item in DeviceList:
        if item['id']==ID:
          temp_dict['name'] = item['name']
          temp_dict['model'] = item['model']
          temp_dict['healthStatus'] = item['healthStatus']
          temp_dict['sw_version'] = item['sw_version']
          temp_dict['license_caps'] = item['license_caps']
          if 'ftdMode' in item: temp_dict['ftdMode'] = item['ftdMode']
          if 'sruVersion' in item['metadata']: temp_dict['sru_version'] = item['metadata']['sruVersion']
          if 'vdbVersion' in item['metadata']: temp_dict['vdb_version'] = item['metadata']['vdbVersion']
          if 'snortVersion' in item['metadata']: temp_dict['snort_version'] = item['metadata']['snortVersion']
          if 'chassisData' in item['metadata']: temp_dict['chassisData'] = item['metadata']['chassisData']
          # Delete item from Device List
          DeviceList.pop(DeviceList.index(item))
    return temp_dict


#
#
#
# Get Net Object UUID
def get_net_object_uuid(server,API_UUID,headers,ObjectName,outfile):
    # Create Get DATA JSON Dictionary to collect data from GET calls
    GetDATA = {}
    GetDATA['items'] = []
    try:
        # Collect Network Objects
        url_get = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networks?offset=0&limit=1000'
        # REST call with SSL verification turned off
        r = requests.get(url_get, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        print(f'Status code is: {status_code}')
        json_resp = r.json()
        if status_code == 200:
            # Loop for First Page of Items
            for item in json_resp['items']:
                # Append Items to New Dictionary
                GetDATA['items'].append({'name': item['name'],'id': item['id']})
            while json_resp['paging'].__contains__('next'):
                url_get = json_resp['paging']['next'][0]
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    resp = r.text
                    print(f'Status code is: {status_code}')
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            GetDATA['items'].append({'name': item['name'],'id': item['id']})
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
                    outfile.write(f'Error occurred in POST --> {resp}\n{ObjectName}\n')
        # Collect Host Objects
        url_get = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/hosts?offset=0&limit=1000'
        # REST call with SSL verification turned off
        r = requests.get(url_get, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        print(f'Status code is: {status_code}')
        json_resp = r.json()
        if status_code == 200:
            # Loop for First Page of Items
            for item in json_resp['items']:
                # Append Items to New Dictionary
                GetDATA['items'].append({'name': item['name'],'id': item['id']})
            while json_resp['paging'].__contains__('next'):
                url_get = json_resp['paging']['next'][0]
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    resp = r.text
                    print(f'Status code is: {status_code}')
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            GetDATA['items'].append({'name': item['name'],'id': item['id']})
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
                    outfile.write(f'Error occurred in POST --> {resp}\n{ObjectName}\n')
                try:
                    if r: r.close()
                except:
                    None
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')
        outfile.write(f'Error occurred in POST --> {resp}\n{ObjectName}\n')
    try:
        if r: r.close()
    except:
        None

    for item in GetDATA['items']:
        if item['name'] == ObjectName:
            # Pull Object UUID from json_resp data
            ObjectID = item['id']
    return ObjectID


#
#
#
# Prompt user to select from options, returns selection
#   L == list of dict items with a 'name' key
def select(opt,L):
    options = {}
    counter = 0
    if L == []:
        L.append({'None':'None'})
    for item in L:
        counter += 1
        if 'None' in item:
            options.update({str(counter):{'key':'None', 'value':'None'}})
        else:
            options.update({str(counter):{'key':item['name'],'value':item}})
    while True:
        print(f'''
#---------------------------------------------------
{opt} options...
#---------------------------------------------------''')
        for k,v in options.items():
            print(f'  {k}: {v["key"]}')
        option = input(f'Select a {opt}: ').lower()
        if option not in options:
            print('Invalid selection....\n')
            continue
        elif options[option]['value'] == 'None':
            return None
        else:
            return options[option]['value']





#
#
#
# Collects and returns items from all pages
def get_items(url,headers):
    try:
        # REST call with SSL verification turned off
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        #print(json.dumps(r.json(),indent=4))
        try:
            temp_list = r.json()['items']
        except:
            return []
        json_resp = r.json()
        #print(f'Json: {json_resp}')
        if status_code == 200:
            while 'next' in json_resp['paging']:
                url_get = json_resp['paging']['next'][0]
                print(f'*\n*\nCOLLECTING NEXT PAGE... {url_get}')
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            temp_list.append(item)
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {traceback.format_exc()}')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {traceback.format_exc()}')
    return temp_list






#
# Parse ACP Rule, return list
def parse_rule(FMC_NAME,rule):
    if 'prefilterPolicy' in rule['metadata']:
        ACP_NAME    = rule['metadata']['prefilterPolicy']['name']
        ACP_TYPE    = rule['metadata']['prefilterPolicy']['type']
        ACP_ID      = rule['metadata']['prefilterPolicy']['id']
    else:
        ACP_NAME    = rule['metadata']['accessPolicy']['name']
        ACP_TYPE    = rule['metadata']['accessPolicy']['type']
        ACP_ID      = rule['metadata']['accessPolicy']['id']
    R_NAME      = rule['name']
    R_ID        = rule['id']
    R_ACTION    = rule['action']
    R_SRC_ZN    = ''
    R_DST_ZN    = ''
    R_SRC_IP    = ''
    R_DST_IP    = ''
    R_VLAN      = ''
    R_USERS     = ''
    R_APP       = 'false'
    R_URL       = 'false'
    R_SRC_P     = ''
    R_DST_P     = ''
    R_SRC_SGT   = ''
    R_DST_SGT   = ''
    R_IPS       = ''
    R_FILE      = ''

    # Source Zones
    if 'sourceZones' in rule:
        temp_list = [i['name'] for i in rule['sourceZones']['objects']]
        if len(temp_list) > 1:
            R_SRC_ZN = '; '.join(temp_list)
        else:
            R_SRC_ZN = temp_list[0]
    # Destination Zones
    if 'destinationZones' in rule:
        temp_list = [i['name'] for i in rule['destinationZones']['objects']]
        if len(temp_list) > 1:
            R_DST_ZN = '; '.join(temp_list)
        else:
            R_DST_ZN = temp_list[0]
    # Source Zones for Prefilter Rules
    if 'sourceInterfaces' in rule:
        temp_list = [i['name'] for i in rule['sourceInterfaces']['objects']]
        if len(temp_list) > 1:
            R_SRC_ZN = '; '.join(temp_list)
        else:
            R_SRC_ZN = temp_list[0]
    # Destination Zones for Prefilter Rules
    if 'destinationInterfaces' in rule:
        temp_list = [i['name'] for i in rule['destinationInterfaces']['objects']]
        if len(temp_list) > 1:
            R_DST_ZN = '; '.join(temp_list)
        else:
            R_DST_ZN = temp_list[0]
    # Source Networks
    if 'sourceNetworks' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['sourceNetworks']:
            temp_list = [i['value'] for i in rule['sourceNetworks']['literals']]
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['sourceNetworks']:
            temp_list = [i['name'] for i in rule['sourceNetworks']['objects']]
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]
        if (lits != '') and (objs != ''):
            R_SRC_IP = '; '.join([lits,objs])
        elif lits != '':
            R_SRC_IP = lits
        elif objs != '':
            R_SRC_IP = objs
    # Destination Networks
    if 'destinationNetworks' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['destinationNetworks']:
            temp_list = [i['value'] for i in rule['destinationNetworks']['literals']]
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['destinationNetworks']:
            temp_list = [i['name'] for i in rule['destinationNetworks']['objects']]
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]
        if (lits != '') and (objs != ''):
            R_DST_IP = '; '.join([lits,objs])
        elif lits != '':
            R_DST_IP = lits
        elif objs != '':
            R_DST_IP = objs
    # VLAN Tags
    if 'vlanTags' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['vlanTags']:
            temp_list = []
            for i in rule['vlanTags']['literals']:
                if i['startTag'] == i['endTag']:
                    temp_list.append(str(i['startTag']))
                else:
                    temp_list.append(f'{i["startTag"]}-{i["endTag"]}')
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['vlanTags']:
            temp_list = [i['name'] for i in rule['vlanTags']['objects']]
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]
        if (lits != '') and (objs != ''):
            R_VLAN = '; '.join([lits,objs])
        elif lits != '':
            R_VLAN = lits
        elif objs != '':
            R_VLAN = objs
    # Users
    if 'users' in rule:
        temp_list = [i['name'] for i in rule['users']['objects']]
        if len(temp_list) > 1:
            R_USERS = '; '.join(temp_list)
        else:
            R_USERS = temp_list[0]
    # Application Filters, Too complext to represent simply.
    # Using true/false to represent if configured or not
    if 'applications' in rule:
        R_APP = 'true'
    # URL Reputation Filters, Too complext to represent simply.
    # Using true/false to represent if configured or not
    if 'urls' in rule:
        R_URL = 'true'
    # Source Ports
    if 'sourcePorts' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['sourcePorts']:
            temp_list = []
            for i in rule['sourcePorts']['literals']:
                if i['protocol'] == '6':
                    temp_list.append(f'TCP:{i["port"]}')
                elif i['protocol'] == '17':
                    temp_list.append(f'UDP:{i["port"]}')
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['sourcePorts']:
            temp_list = [i['name'] for i in rule['sourcePorts']['objects']]
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]
        if (lits != '') and (objs != ''):
            R_SRC_P = '; '.join([lits,objs])
        elif lits != '':
            R_SRC_P = lits
        elif objs != '':
            R_SRC_P = objs
    # Destination Ports
    if 'destinationPorts' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['destinationPorts']:
            temp_list = []
            for i in rule['destinationPorts']['literals']:
                if i['protocol'] == '6':
                    temp_list.append(f'TCP:{i["port"]}')
                elif i['protocol'] == '17':
                    temp_list.append(f'UDP:{i["port"]}')
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['destinationPorts']:
            temp_list = [i['name'] for i in rule['destinationPorts']['objects']]
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]
        if (lits != '') and (objs != ''):
            R_DST_P = '; '.join([lits,objs])
        elif lits != '':
            R_DST_P = lits
        elif objs != '':
            R_DST_P = objs
    # Encapsulation Ports, equivalent to Destination Ports for Prefilter
    if 'encapsulationPorts' in rule:
        if len(rule['encapsulationPorts']) > 1:
            R_DST_P = '; '.join(rule['encapsulationPorts'])
        else:
            R_DST_P = rule['encapsulationPorts'][0]
    # Source SGTs
    if 'sourceSecurityGroupTags' in rule:
        temp_list = [i['name'] for i in rule['sourceSecurityGroupTags']['objects']]
        if len(temp_list) > 1:
            R_SRC_SGT = '; '.join(temp_list)
        else:
            R_SRC_SGT = temp_list[0]
    # Destination SGTs
    if 'destinationSecurityGroupTags' in rule:
        temp_list = [i['name'] for i in rule['destinationSecurityGroupTags']['objects']]
        if len(temp_list) > 1:
            R_DST_SGT = '; '.join(temp_list)
        else:
            R_DST_SGT = temp_list[0]
    # IPS Policy
    if 'ipsPolicy' in rule:
        R_IPS = rule['ipsPolicy']['name']
    # File Policy
    if 'filePolicy' in rule:
        R_FILE = rule['filePolicy']['name']

    temp_list = [
        FMC_NAME,
        ACP_NAME,
        ACP_TYPE,
        ACP_ID,
        R_NAME,
        R_ID,
        R_ACTION,
        R_SRC_ZN,
        R_DST_ZN,
        R_SRC_IP,
        R_DST_IP,
        R_VLAN,
        R_USERS,
        R_APP,
        R_URL,
        R_SRC_P,
        R_DST_P,
        R_SRC_SGT,
        R_DST_SGT,
        R_IPS,
        R_FILE,
    ]
    return temp_list

