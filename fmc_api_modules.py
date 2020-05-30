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


#
#
#
# Define Password Function
def define_password():
    password = None
    while not password:
        password = getpass.getpass('Please Enter API Password: ')
        passwordverify = getpass.getpass('Re-enter API Password to Verify: ')
        if not password == passwordverify:
            print('Passwords Did Not Match Please Try Again')
            password = None
    return password

#
#
#
# Define Generate Access Token Function
def AccessToken(server,headers,username,password):
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
        print (f'Error in generating auth token --> {err}')
        sys.exit()
    return auth_token,domains

#
#
# Get Device Details from Inventory List
# And Delete item from Inventory List
def GetDeviceDetails(ID,DeviceList):
  temp_dict = {}
  for item in DeviceList:
    if item['id']==ID:
      temp_dict['name'] = item['name']
      temp_dict['model'] = item['model']
      temp_dict['healthStatus'] = item['healthStatus']
      temp_dict['sw_version'] = item['sw_version']
      temp_dict['license_caps'] = item['license_caps']
      if 'chassisData' in item['metadata']: temp_dict['chassisData'] = item['metadata']['chassisData']
      # Delete item from Device List
      DeviceList.pop(DeviceList.index(item))
  return temp_dict


#
#
#
# Get Net Object UUID
def GetNetObjectUUID(server,API_UUID,headers,ObjectName,outfile):
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

