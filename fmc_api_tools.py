# Import Required Modules
import os,\
        re,\
        sys,\
        csv,\
        json,\
        socket,\
        random,\
        netaddr,\
        getpass,\
        requests,\
        traceback

# Import custom modules from file
from fmc_api_modules import \
        define_password,\
        AccessToken,\
        GetDeviceDetails,\
        GetNetObjectUUID, \
        listToString

#
#
#
# Define Blank URL Get Script as Function
def BlankGet(server,headers,username,password):
    print ('''
***********************************************************************************************
*                             Basic URL GET Script                                            *
*_____________________________________________________________________________________________*
*                                                                                             *
* USER INPUT NEEDED:                                                                          *
*                                                                                             *
*  1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/{object_UUID})   *
*                                                                                             *
*  2. Expand output to show details of each object *(Not Supported with {object_UUID} GET)    *
*                                                                                             *
*  3. Limit output to a specific number of objects *(Not Supported with {object_UUID} GET)    *
*                                                                                             *
*  4. Save output to file                                                                     *
*                                                                                             *
*                                                                                             *
***********************************************************************************************
''')

    print('Generating Access Token')
    # Generate Access Token and pull domains from auth headers
    results=AccessToken(server,headers,username,password)
    headers['X-auth-access-token']=results[0]

    # Request API URI Path
    api_path = input('Please Enter URI: ').lower().strip()

    # Clean URI
    if (api_path[-1] == '/'):
        api_path = api_path[:-1]

    # Check for GETBYID Operation in URI
    getbyid = re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', api_path[-36:])

    # Set URL
    url = f'{server}{api_path}'

    # Ask to Expand and/or assign output Limit
    if getbyid == None:
        expand = input('Would You Like To Expand Output Entries? [y/N]: ').lower()
        limit = input('Would You Like To Limit Output Entries? [Number or "No"]: ').lower()

        if limit not in (['no','n','']) and expand in (['yes','ye','y']):
            url = f'{server}{api_path}?expanded=true&limit={limit}'
        elif limit not in (['no','n','']) and expand in (['no','n','']):
            url = f'{server}{api_path}?limit={limit}'
        elif limit in (['no','n','']) and expand in (['yes','ye','y']):
            url = f'{server}{api_path}?expanded=true'
    if url[-1] == '/':
        url = url[:-1]

    # Perform API GET call
    print(f'Performing API GET to: {url}')
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.json()
        if (status_code == 200):
            print('GET successful...')
            # Ask if output should be saved to File
            save = input('Would You Like To Save The Output To File? [y/N]: ').lower()
            if save in (['yes','ye','y']):
                # Random Generated JSON Output File
                filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
                filename += '.json'
                print(f'*\n*\nRANDOM LOG FILE CREATED... {filename}\n')
                with open(filename, 'a') as OutFile:
                    OutFile.write(json.dumps(resp,indent=4))
            elif save in (['no','n','']):
                print(json.dumps(resp,indent=4))
        else:
            r.raise_for_status()
            print(f'Error occurred in GET --> {resp}')
    except requests.exceptions.HTTPError as err:
        print(f'Error in connection --> {err}')
        print(json.dumps(resp,indent=4))
    # End
    finally:
        try:
            if r: r.close()
        except:
            None


#
#
#
# Define Network Object POST Script as Funtion
def PostNetworkObject(server,headers,username,password):
    print ('''
***********************************************************************************************
*                          Create Network Objects in bulk                                     *
*_____________________________________________________________________________________________*
*                                                                                             *
* USER INPUT NEEDED:                                                                          *
*                                                                                             *
*  1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networks/)                     *
*                                                                                             *
*  2. CSV Data Input file                                                                     *
*          #CSV FORMAT - No Header Row: Column0 = ObjectName, Column1 = Address               *
*                                                                                             *
***********************************************************************************************
''')
    print('Generating Access Token')
    # Generate Access Token and pull domains from auth headers
    results=AccessToken(server,headers,username,password)
    headers['X-auth-access-token']=results[0]

    # Request API URI Path
    api_path = input('Please Enter URI: ').lower().strip()

    # Clean URI
    if (api_path[-1] == '/'):
        api_path = api_path[:-1]

    Test = False
    while not Test:
        # Request Input File
        read_csv = input('Please Enter Input File /full/file/path.csv: ')
        if os.path.isfile(read_csv):
            # Read csv file
            open_read_csv = open(read_csv, 'rb')
            my_csv_reader = csv.reader(open_read_csv, delimiter=',')
            Test = True
        else:
            print('MUST PROVIDE INPUT FILE...')

    # Random Generated JSON Output File
    filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
    filename += '.json'
    print(f'*\n*\nRANDOM LOG FILE CREATED... {filename}\n')

    # Combine Server and API Path
    url = f'{server}{api_path}'

    # Clean URL
    if url[-1] == '/':
        url = url[:-1]

    # Creat For Loop To Process Each Item In CSV
    for row in my_csv_reader:
        # Pull Object Name and Address from CSV
        ObjectName = row[0]
        Address = row[1]
        post_data = {
        'name': ObjectName,
        'type': 'Network',
        'description': '',
        'value': Address
        }

        try:
            # REST call with SSL verification turned off:
            r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            print(f'Status code is: {status_code}')
            if status_code == 201 or status_code == 202:
                print('Items Processing... View Output File For Full Change Log...')
                json_resp = json.loads(resp)
                outfile.write(json.dumps(json.loads(resp),indent=4))
            else :
                r.raise_for_status()
                print ('Error occurred in POST --> {resp}')
        except requests.exceptions.HTTPError as err:
            print ('Error in connection --> {err}')
        finally:
            try:
                if r: r.close()
            except:
                None

#
#
#
# Define Network Object-Group POST Script as Funtion
def PostNetworkObjectGroup(server,headers,username,password):
    print ('''
***********************************************************************************************
*                Create Network Objects in bulk and add to new Object-Group                   *
*_____________________________________________________________________________________________*
*                                                                                             *
* USER INPUT NEEDED:                                                                          *
*                                                                                             *
*  1. TXT Data Input file (ASA "show run object-group" output)                                *
*                                                                                             *
***********************************************************************************************
''')

    print('Generating Access Token')
    # Generate Access Token and pull domains from auth headers
    results=AccessToken(server,headers,username,password)
    headers['X-auth-access-token']=results[0]
    domains = results[1]

    Test = False
    if len(domains) > 1:
        while not Test:
            print('Multiple FMC domains found:')
            for domain in domains:
                print(f'    {domain["name"]}')
            choice = input('\nPlease select an FMC domain: ').strip()
            for domain in domains:
                if choice in domain['name']:
                    API_UUID = domain['uuid']
                    Test=True
            if not Test:
                print('Invalid Selection...\n')
    else:
        API_UUID = domains[0]['uuid']

    Test = False
    while not Test:
        # Request Input File
        read_file = input('Please Enter Input File /full/file/path.txt: ').strip()
        if os.path.isfile(read_file):
            # Read csv file
            open_read_file = open(read_file, 'r').read()
            Test = True
        else:
            print('MUST PROVIDE INPUT FILE...')

    # Random Generated JSON Output File
    filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
    filename += '.json'
    print(f'*\n*\nRANDOM LOG FILE CREATED... {filename}\n')
    outfile = open(filename,'w')

    # Define Counters
    NetOb_Counter = 0
    ObGr_Counter = 0
    ObGr = False
    # Create For Loop To Process Each Item In CSV
    for item in open_read_file.splitlines():
        # Find Object-Group Name
        if item.startswith('object-group network '):
            if ObGr:
                # Post existing Object-Group JSON, and reset counters
                NetOb_Counter = 0
                ObGr_Counter = 0
                url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                # ReDefine Original Object-Group Name
                ObGr_NAME = ObGr_NAME_Orig
                ObGr_json_Size = json.dumps(ObGr_json)
                # Perform POST for Obect-Group
                try:
                    # REST call with SSL verification turned off:
                    r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                    status_code = r.status_code
                    resp = r.text
                    json_resp = json.loads(resp)
                    print(f'Status code is: {status_code}')
                    if status_code == 201 or status_code == 202:
                        print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                        # Append Object-Group JSON with new entry for Network-Object
                        outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                    else :
                        json_resp = json.loads(resp)
                        r.raise_for_status()
                        print(f'Error occurred in POST --> {resp}{ObjectName}')
                        outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                finally:
                    try:
                        if r: r.close()
                    except:
                        None

            # Create New Object-Group JSON
            ObGr = True
            ObGr_NAME_Orig = item.strip('object-group network ')
            ObGr_NAME = ObGr_NAME_Orig
            # Create Base JSON data for Object-Group
            ObGr_json = {
            'name': ObGr_NAME,
            'objects': [],
            'type': 'NetworkGroup'
            }







           # # Create Network-Object JSON Data RANGE
           # post_data = {
           # 'name': ObjectName,
           # 'type': 'Range',
           # 'description': '',
           # 'value': '1.1.1.1-1.1.1.2'
           # }





        # Process Host Entries
        elif item.startswith(' network-object host '):
            Address = item.strip(' network-object host ')
            # Define Network-Object Name
            ObjectName = f'host-{Address}'
            # Create Network-Object JSON Data
            post_data = {
            'name': ObjectName,
            'type': 'Host',
            'description': '',
            'value': Address
            }
            # Define Network-Object Counter
            NetOb_Counter += 1
            if NetOb_Counter in list(range(50,2000,50)):
                ## Generate Access Token
                print ('Attempting to Renew Token...')
                results=AccessToken(server,headers,username,password)
                headers['X-auth-access-token']=results[0]
            # Perform POST for each Network-Object
            try:
                # Format URL for Network-Object POST
                url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/hosts'
                # REST call with SSL verification turned off:
                r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                print(f'[{NetOb_Counter}] Network-Object Processing... View Output File For Full Change Log...')
                print(f'Status code is: {status_code}')
                json_resp = json.loads(resp)
                if status_code == 201 or status_code == 202:
                    # Pull Object UUID from json_resp data
                    ObjectID = json_resp ['id']
                    # Append Object-Group JSON with new entry for Network-Object
                    ObGr_json['objects'].append({'type': 'Host','id': ObjectID})
                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n')
                    # Set JSON Data for checking DUMP size
                    ObGr_json_Size = json.dumps(ObGr_json)
                    # Validate size of JSON Data
                    if sys.getsizeof(ObGr_json_Size) >= 20000:
                        print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                        outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                        # Increase Object-Group Counter
                        ObGr_Counter += 1
                        # Add Counter To Group Name
                        ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                        ObGr_json['name'] = ObGr_Count
                        # Format URL for Object-Group POST
                        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                        # Perform POST for Obect-Group
                        try:
                            # REST call with SSL verification turned off:
                            r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                            status_code = r.status_code
                            resp = r.text
                            json_resp = json.loads(resp)
                            print(f'Status code is: {status_code}')
                            if status_code == 201 or status_code == 202:
                                print('Object-Group Processing... View Output File For Full Change Log...')
                                # Append Object-Group JSON with new entry for Network-Object
                                outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                # Reset Object-Group Data
                                ObGr_Data = None
                                ObGr_Data = {
                                'name': ObGr_NAME,
                                'objects': [],
                                'type': 'NetworkGroup'
                                }
                                # Read Object-Group JSON data for Editing
                                ObGr_json = json.loads(json.dumps(ObGr_Data))
                            else :
                                json_resp = json.loads(resp)
                                r.raise_for_status()
                                print (f'Error occurred in POST --> {resp}{ObjectName}')
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                        except requests.exceptions.HTTPError as err:
                            print (f'Error in connection --> {err}')
                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                        finally:
                            try:
                                if r: r.close()
                            except:
                                None
                else :
                    r.raise_for_status()
                    outfile.write(f'Error occurred in POST --> {json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
                    print(f'Error occurred in POST --> {json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
            except requests.exceptions.HTTPError as err:
                json_resp = json.loads(resp)
                print(f'Error in connection -->{err}')
                outfile.write(f'Error in connection --> {err}\n{json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
                for item in json_resp['error']['messages']:
                    # Error Handling for Network-Object that already exists
                    if 'already exists' in item['description']:
                        print(f'Network Object Already Exists... Attempting to Get UUID for {ObjectName}')

                        # Perform GET to grab UUID for Network Object that already exists
                        ObjectID = GetNetObjectUUID(server,API_UUID,headers,ObjectName,outfile)

                        # Append Object-Group JSON with new entry for Network-Object
                        ObGr_json['objects'].append({'type': 'Network','id': ObjectID})
                        outfile.write(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n')

                        # Set JSON Data for checking DUMP size
                        ObGr_json_Size = json.dumps(ObGr_json)

                        # Validate size of JSON Data
                        if sys.getsizeof(ObGr_json_Size) >= 20000:
                            print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                            outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                            # Increase Object-Group Counter
                            ObGr_Counter += 1

                            # Run Object Object-Group Creation
                            #ObGr_Data = LargeObGrPost()

                            # Add Counter To Group Name
                            ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                            ObGr_json['name'] = ObGr_Count
                            # Format URL for Object-Group POST
                            url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                            # Perform POST for Obect-Group
                            try:
                                # REST call with SSL verification turned off:
                                r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                status_code = r.status_code
                                resp = r.text
                                json_resp = json.loads(resp)
                                print(f'Status code is: {status_code}')
                                if status_code == 201 or status_code == 202:
                                    print('Object-Group Processing... View Output File For Full Change Log...')
                                    # Append Object-Group JSON with new entry for Network-Object
                                    outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                    # Reset Object-Group Data
                                    ObGr_Data = None
                                    ObGr_Data = {
                                    'name': ObGr_NAME,
                                    'objects': [],
                                    'type': 'NetworkGroup'
                                    }
                                    # Read Object-Group JSON data for Editing
                                    ObGr_json = json.loads(json.dumps(ObGr_Data))
                                else :
                                    json_resp = json.loads(resp)
                                    r.raise_for_status()
                                    print (f'Error occurred in POST --> {resp}{ObjectName}')
                                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                            except requests.exceptions.HTTPError as err:
                                print (f'Error in connection --> {err}')
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                            finally:
                                try:
                                    if r: r.close()
                                except:
                                    None

                    # Error Handling for Access Token Timeout
                    elif 'Access token invalid' in item['description']:
                        print ('Access token invalid... Attempting to Renew Token...')
                        results=AccessToken(server,headers,username,password)
                        headers['X-auth-access-token']=results[0]

                        # Perform POST for each Network-Object
                        try:
                            # Format URL for Network-Object POST
                            url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/hostss'
                            # REST call with SSL verification turned off:
                            r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
                            # REST call with SSL verification turned on:
                            # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
                            status_code = r.status_code
                            resp = r.text
                            print('['+str(NetOb_Counter)+'] Network-Object Processing... View Output File For Full Change Log...')
                            print(f'Status code is: {status_code}')
                            json_resp = json.loads(resp)
                            if status_code == 201 or status_code == 202:
                                # Pull Object UUID from json_resp data
                                ObjectID = json_resp ['id']
                                # Append Object-Group JSON with new entry for Network-Object
                                ObGr_json['objects'].append({'type': 'Host','id': ObjectID})
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n')
                                # Set JSON Data for checking DUMP size
                                ObGr_json_Size = json.dumps(ObGr_json)
                                # Validate size of JSON Data
                                if sys.getsizeof(ObGr_json_Size) >= 20000:
                                    print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                                    outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                                    # Increase Object-Group Counter
                                    ObGr_Counter = ObGr_Counter + 1

                                    # Run Object Object-Group Creation
                                    #ObGr_Data = LargeObGrPost()

                                    # Add Counter To Group Name
                                    ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                                    ObGr_json['name'] = ObGr_Count
                                    # Format URL for Object-Group POST
                                    url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                                    # Perform POST for Obect-Group
                                    try:
                                        # REST call with SSL verification turned off:
                                        r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                        status_code = r.status_code
                                        resp = r.text
                                        json_resp = json.loads(resp)
                                        print(f'Status code is: {status_code}')
                                        if status_code == 201 or status_code == 202:
                                            print('Object-Group Processing... View Output File For Full Change Log...')
                                            # Append Object-Group JSON with new entry for Network-Object
                                            outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                            # Reset Object-Group Data
                                            ObGr_Data = None
                                            ObGr_Data = {
                                            'name': ObGr_NAME,
                                            'objects': [],
                                            'type': 'NetworkGroup'
                                            }
                                            # Read Object-Group JSON data for Editing
                                            ObGr_json = json.loads(json.dumps(ObGr_Data))
                                        else :
                                            json_resp = json.loads(resp)
                                            r.raise_for_status()
                                            print (f'Error occurred in POST --> {resp}{ObjectName}')
                                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                                    except requests.exceptions.HTTPError as err:
                                        print (f'Error in connection --> {err}')
                                        outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                                    finally:
                                        try:
                                            if r: r.close()
                                        except:
                                            None
                            else :
                                r.raise_for_status()
                                outfile.write('Error occurred in POST --> '+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                                print ('Error occurred in POST --> '+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                        except requests.exceptions.HTTPError as err:
                            json_resp = json.loads(resp)
                            print (f'Error in connection --> {err}')
                            outfile.write(f'Error in connection --> {err}'+'\n'+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                            for item in json_resp['error']['messages']:
                                # Error Handling for Network-Object that already exists
                                if 'already exists' in item['description']:
                                    print(f'Network Object Already Exists... Attempting to Get UUID for {ObjectName}')

                                    # Perform GET to grab UUID for Network Object that already exists
                                    ObjectID = GetNetObjectUUID(server,API_UUID,headers,ObjectName,outfile)

                                    # Append Object-Group JSON with new entry for Network-Object
                                    ObGr_json['objects'].append({'type': 'Host','id': ObjectID})
                                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n')

                                    # Set JSON Data for checking DUMP size
                                    ObGr_json_Size = json.dumps(ObGr_json)

                                    # Validate size of JSON Data
                                    if sys.getsizeof(ObGr_json_Size) >= 20000:
                                        print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                                        outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                                        # Increase Object-Group Counter
                                        ObGr_Counter += 1

                                        # Run Object Object-Group Creation
                                        #ObGr_Data = LargeObGrPost()

                                        # Add Counter To Group Name
                                        ObGr_Count = ObGr_NAME+'-'+str(ObGr_Counter)
                                        ObGr_json['name'] = ObGr_Count
                                        # Format URL for Object-Group POST
                                        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                                        # Perform POST for Obect-Group
                                        try:
                                            # REST call with SSL verification turned off:
                                            r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                            status_code = r.status_code
                                            resp = r.text
                                            json_resp = json.loads(resp)
                                            print(f'Status code is: {status_code}')
                                            if status_code == 201 or status_code == 202:

                                                print('Object-Group Processing... View Output File For Full Change Log...')
                                                # Append Object-Group JSON with new entry for Network-Object

                                                outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                                # Reset Object-Group Data
                                                ObGr_Data = None
                                                ObGr_Data = {
                                                'name': ObGr_NAME,
                                                'objects': [],
                                                'type': 'NetworkGroup'
                                                }
                                                # Read Object-Group JSON data for Editing
                                                ObGr_json = json.loads(json.dumps(ObGr_Data))
                                            else :
                                                json_resp = json.loads(resp)
                                                r.raise_for_status()
                                                print(f'Error occurred in POST --> {resp}{ObjectName}')
                                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                                        except requests.exceptions.HTTPError as err:
                                            print (f'Error in connection --> {err}')
                                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                                        finally:
                                            try:
                                                if r: r.close()
                                            except:
                                                None
                        finally:
                            try:
                                if r: r.close()
                            except:
                                None

        # Process Network Entries
        elif item.startswith(' network-object '):
            net = item.strip(' network-object ').replace(' ','/')
            # Convert Netmask to CIDR notation
            Address = netaddr.IPNetwork(net).cidr
            # Define Network-Object Name
            ObjectName = f'net-{str(Address).replace("/","n")}'
            # Create Network-Object JSON Data
            post_data = {
            'name': ObjectName,
            'type': 'Network',
            'description': '',
            'value': str(Address)
            }
            # Define Network-Object Counter
            NetOb_Counter += 1
            if NetOb_Counter in list(range(50,2000,50)):
                ## Generate Access Token
                print ('Attempting to Renew Token...')
                results=AccessToken(server,headers,username,password)
                headers['X-auth-access-token']=results[0]
            # Perform POST for each Network-Object
            try:
                # Format URL for Network-Object POST
                url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networks'
                # REST call with SSL verification turned off:
                r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
                status_code = r.status_code
                resp = r.text
                print(f'[{NetOb_Counter}] Network-Object Processing... View Output File For Full Change Log...')
                print(f'Status code is: {status_code}')
                json_resp = json.loads(resp)
                if status_code == 201 or status_code == 202:
                    # Pull Object UUID from json_resp data
                    ObjectID = json_resp ['id']
                    # Append Object-Group JSON with new entry for Network-Object
                    ObGr_json['objects'].append({'type': 'Network','id': ObjectID})
                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n')
                    # Set JSON Data for checking DUMP size
                    ObGr_json_Size = json.dumps(ObGr_json)
                    # Validate size of JSON Data
                    if sys.getsizeof(ObGr_json_Size) >= 20000:
                        print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                        outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                        # Increase Object-Group Counter
                        ObGr_Counter += 1
                        # Add Counter To Group Name
                        ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                        ObGr_json['name'] = ObGr_Count
                        # Format URL for Object-Group POST
                        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                        # Perform POST for Obect-Group
                        try:
                            # REST call with SSL verification turned off:
                            r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                            status_code = r.status_code
                            resp = r.text
                            json_resp = json.loads(resp)
                            print(f'Status code is: {status_code}')
                            if status_code == 201 or status_code == 202:
                                print('Object-Group Processing... View Output File For Full Change Log...')
                                # Append Object-Group JSON with new entry for Network-Object
                                outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                # Reset Object-Group Data
                                ObGr_Data = None
                                ObGr_Data = {
                                'name': ObGr_NAME,
                                'objects': [],
                                'type': 'NetworkGroup'
                                }
                                # Read Object-Group JSON data for Editing
                                ObGr_json = json.loads(json.dumps(ObGr_Data))
                            else :
                                json_resp = json.loads(resp)
                                r.raise_for_status()
                                print (f'Error occurred in POST --> {resp}{ObjectName}')
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                        except requests.exceptions.HTTPError as err:
                            print (f'Error in connection --> {err}')
                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                        finally:
                            try:
                                if r: r.close()
                            except:
                                None
                else :
                    r.raise_for_status()
                    outfile.write(f'Error occurred in POST --> {json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
                    print(f'Error occurred in POST --> {json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
            except requests.exceptions.HTTPError as err:
                json_resp = json.loads(resp)
                print(f'Error in connection -->{err}')
                outfile.write(f'Error in connection --> {err}\n{json.dumps(json_resp,indent=4)}\n{ObjectName}\n')
                for item in json_resp['error']['messages']:
                    # Error Handling for Network-Object that already exists
                    if 'already exists' in item['description']:
                        print(f'Network Object Already Exists... Attempting to Get UUID for {ObjectName}')

                        # Perform GET to grab UUID for Network Object that already exists
                        ObjectID = GetNetObjectUUID(server,API_UUID,headers,ObjectName,outfile)

                        # Append Object-Group JSON with new entry for Network-Object
                        ObGr_json['objects'].append({'type': 'Network','id': ObjectID})
                        outfile.write(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n')

                        # Set JSON Data for checking DUMP size
                        ObGr_json_Size = json.dumps(ObGr_json)

                        # Validate size of JSON Data
                        if sys.getsizeof(ObGr_json_Size) >= 20000:
                            print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                            outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                            # Increase Object-Group Counter
                            ObGr_Counter += 1

                            # Run Object Object-Group Creation
                            #ObGr_Data = LargeObGrPost()

                            # Add Counter To Group Name
                            ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                            ObGr_json['name'] = ObGr_Count
                            # Format URL for Object-Group POST
                            url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                            # Perform POST for Obect-Group
                            try:
                                # REST call with SSL verification turned off:
                                r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                status_code = r.status_code
                                resp = r.text
                                json_resp = json.loads(resp)
                                print(f'Status code is: {status_code}')
                                if status_code == 201 or status_code == 202:
                                    print('Object-Group Processing... View Output File For Full Change Log...')
                                    # Append Object-Group JSON with new entry for Network-Object
                                    outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                    # Reset Object-Group Data
                                    ObGr_Data = None
                                    ObGr_Data = {
                                    'name': ObGr_NAME,
                                    'objects': [],
                                    'type': 'NetworkGroup'
                                    }
                                    # Read Object-Group JSON data for Editing
                                    ObGr_json = json.loads(json.dumps(ObGr_Data))
                                else :
                                    json_resp = json.loads(resp)
                                    r.raise_for_status()
                                    print (f'Error occurred in POST --> {resp}{ObjectName}')
                                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                            except requests.exceptions.HTTPError as err:
                                print (f'Error in connection --> {err}')
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                            finally:
                                try:
                                    if r: r.close()
                                except:
                                    None

                    # Error Handling for Access Token Timeout
                    elif 'Access token invalid' in item['description']:
                        print ('Access token invalid... Attempting to Renew Token...')
                        results=AccessToken(server,headers,username,password)
                        headers['X-auth-access-token']=results[0]

                        # Perform POST for each Network-Object
                        try:
                            # Format URL for Network-Object POST
                            url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networks'
                            # REST call with SSL verification turned off:
                            r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
                            # REST call with SSL verification turned on:
                            # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
                            status_code = r.status_code
                            resp = r.text
                            print('['+str(NetOb_Counter)+'] Network-Object Processing... View Output File For Full Change Log...')
                            print(f'Status code is: {status_code}')
                            json_resp = json.loads(resp)
                            if status_code == 201 or status_code == 202:
                                # Pull Object UUID from json_resp data
                                ObjectID = json_resp ['id']
                                # Append Object-Group JSON with new entry for Network-Object
                                ObGr_json['objects'].append({'type': 'Network','id': ObjectID})
                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n')
                                # Set JSON Data for checking DUMP size
                                ObGr_json_Size = json.dumps(ObGr_json)
                                # Validate size of JSON Data
                                if sys.getsizeof(ObGr_json_Size) >= 20000:
                                    print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                                    outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                                    # Increase Object-Group Counter
                                    ObGr_Counter = ObGr_Counter + 1

                                    # Run Object Object-Group Creation
                                    #ObGr_Data = LargeObGrPost()

                                    # Add Counter To Group Name
                                    ObGr_Count = f'{ObGr_NAME}-{ObGr_Counter}'
                                    ObGr_json['name'] = ObGr_Count
                                    # Format URL for Object-Group POST
                                    url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                                    # Perform POST for Obect-Group
                                    try:
                                        # REST call with SSL verification turned off:
                                        r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                        status_code = r.status_code
                                        resp = r.text
                                        json_resp = json.loads(resp)
                                        print(f'Status code is: {status_code}')
                                        if status_code == 201 or status_code == 202:
                                            print('Object-Group Processing... View Output File For Full Change Log...')
                                            # Append Object-Group JSON with new entry for Network-Object
                                            outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                            # Reset Object-Group Data
                                            ObGr_Data = None
                                            ObGr_Data = {
                                            'name': ObGr_NAME,
                                            'objects': [],
                                            'type': 'NetworkGroup'
                                            }
                                            # Read Object-Group JSON data for Editing
                                            ObGr_json = json.loads(json.dumps(ObGr_Data))
                                        else :
                                            json_resp = json.loads(resp)
                                            r.raise_for_status()
                                            print (f'Error occurred in POST --> {resp}{ObjectName}')
                                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                                    except requests.exceptions.HTTPError as err:
                                        print (f'Error in connection --> {err}')
                                        outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                                    finally:
                                        try:
                                            if r: r.close()
                                        except:
                                            None
                            else :
                                r.raise_for_status()
                                outfile.write('Error occurred in POST --> '+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                                print ('Error occurred in POST --> '+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                        except requests.exceptions.HTTPError as err:
                            json_resp = json.loads(resp)
                            print (f'Error in connection --> {err}')
                            outfile.write(f'Error in connection --> {err}'+'\n'+json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))+'\n'+ObjectName+'\n')
                            for item in json_resp['error']['messages']:
                                # Error Handling for Network-Object that already exists
                                if 'already exists' in item['description']:
                                    print(f'Network Object Already Exists... Attempting to Get UUID for {ObjectName}')

                                    # Perform GET to grab UUID for Network Object that already exists
                                    ObjectID = GetNetObjectUUID(server,API_UUID,headers,ObjectName,outfile)

                                    # Append Object-Group JSON with new entry for Network-Object
                                    ObGr_json['objects'].append({'type': 'Network','id': ObjectID})
                                    outfile.write(f'{json.dumps(json_resp,indent=4)}\n')

                                    # Set JSON Data for checking DUMP size
                                    ObGr_json_Size = json.dumps(ObGr_json)

                                    # Validate size of JSON Data
                                    if sys.getsizeof(ObGr_json_Size) >= 20000:
                                        print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
                                        outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
                                        # Increase Object-Group Counter
                                        ObGr_Counter += 1

                                        # Run Object Object-Group Creation
                                        #ObGr_Data = LargeObGrPost()

                                        # Add Counter To Group Name
                                        ObGr_Count = ObGr_NAME+'-'+str(ObGr_Counter)
                                        ObGr_json['name'] = ObGr_Count
                                        # Format URL for Object-Group POST
                                        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
                                        # Perform POST for Obect-Group
                                        try:
                                            # REST call with SSL verification turned off:
                                            r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
                                            # REST call with SSL verification turned on:
                                            # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
                                            status_code = r.status_code
                                            resp = r.text
                                            json_resp = json.loads(resp)
                                            print(f'Status code is: {status_code}')
                                            if status_code == 201 or status_code == 202:

                                                print('Object-Group Processing... View Output File For Full Change Log...')
                                                # Append Object-Group JSON with new entry for Network-Object

                                                outfile.write(f'Object-Group Created...\n{ObGr_Count}\n{json.dumps(json_resp,indent=4)}\n')
                                                # Reset Object-Group Data
                                                ObGr_Data = None
                                                ObGr_Data = {
                                                'name': ObGr_NAME,
                                                'objects': [],
                                                'type': 'NetworkGroup'
                                                }
                                                # Read Object-Group JSON data for Editing
                                                ObGr_json = json.loads(json.dumps(ObGr_Data))
                                            else :
                                                json_resp = json.loads(resp)
                                                r.raise_for_status()
                                                print(f'Error occurred in POST --> {resp}{ObjectName}')
                                                outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
                                        except requests.exceptions.HTTPError as err:
                                            print (f'Error in connection --> {err}')
                                            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')

                                        finally:
                                            try:
                                                if r: r.close()
                                            except:
                                                None
                        finally:
                            try:
                                if r: r.close()
                            except:
                                None


    # Post Final Object-Group
    url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/object/networkgroups'
    # ReDefine Original Object-Group Name
    ObGr_NAME = ObGr_NAME_Orig
    ObGr_json_Size = json.dumps(ObGr_json)
    # Perform POST for Obect-Group
    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(ObGr_json), headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        json_resp = json.loads(resp)
        print(f'Status code is: {status_code}')
        if status_code == 201 or status_code == 202:
            print(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... View Output File For Full Change Log...\n{"*"*95}')
            # Append Object-Group JSON with new entry for Network-Object
            outfile.write(f'{"*"*95}\nObject-Group Size {sys.getsizeof(ObGr_json_Size)}B, Processing Now... \n{json.dumps(ObGr_json,indent=4)}\n{"*"*95}')
        else :
            json_resp = json.loads(resp)
            r.raise_for_status()
            print(f'Error occurred in POST --> {resp}{ObjectName}')
            outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')
        outfile.write(f'{json.dumps(json_resp,indent=4)}\n{ObGr_NAME}\n')
    finally:
        try:
            if r: r.close()
        except:
            None

    outfile.close()

#
#
#
# Define IPS/File Policy Put Script as Funtion
def PutIntrusionFile(server,headers,username,password):
    print ('''
***********************************************************************************************
*                     Update IPS and/or File Policy for Access Rules                          *
*_____________________________________________________________________________________________*
*                                                                                             *
* USER INPUT NEEDED:                                                                          *
*                                                                                             *
*  1. Access Policy UUID                                                                      *
*           (/api/fmc_config/v1/domain/{domain_UUID}/policy/accesspolicies/{ACP_UUID})        *
*                                                                                             *
*  2. Intrusion Policy (Yes/No)                                                               *
*                                                                                             *
*  3. File Policy (Yes/No)                                                                    *
*                                                                                             *
***********************************************************************************************
''')

    print('Generating Access Token')
    # Generate Access Token and pull domains from auth headers
    results=AccessToken(server,headers,username,password)
    headers['X-auth-access-token']=results[0]
    domains = results[1]

    Test = False
    if len(domains) > 1:
        while not Test:
            print('Multiple FMC domains found:')
            for domain in domains:
                print(f'    {domain["name"]}')
            choice = input('\nPlease select an FMC domain: ').strip()
            for domain in domains:
                if choice in domain['name']:
                    API_UUID = domain['uuid']
                    Test=True
            if not Test:
                print('Invalid Selection...\n')
    else:
        API_UUID = domains[0]['uuid']

    Test = False
    while not Test:
        # Request API URI Path
        ACP_UUID = input('Please Enter Access-Policy UUID: ').lower().strip()
        if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', ACP_UUID):
            Test=True
        else:
            print('Invalid UUID...')

    # Create Get DATA JSON Dictionary to collect data from GET calls
    print('*\n*\nCOLLECTING ACCESS-POLICY...')
    try:
        # REST call with SSL verification turned off
        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/policy/accesspolicies/{ACP_UUID}/accessrules?offset=0&limit=1000&expanded=true'
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        print(f'Status code is: {status_code}')
        ACP_DATA = r.json()
        json_resp = r.json()
        if status_code == 200:
            while 'next' in json_resp['paging']:
                url_get = json_resp['paging']['next'][0]
                print(f'*\n*\nCOLLECTING NEXT ACCESS-POLICY PAGE... {url_get}')
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    print(f'Status code is: {status_code}')
                    if status_code == 200:
                        # Loop for First Page of Items
                        json_resp = r.json()
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            ACP_DATA['items'].append(item)
                except requests.exceptions.HTTPError:
                    err_resp = r.json()
                    for item in err_resp['error']['messages']:
                        # Error Handling for Access Token Timeout
                        if 'Access token invalid' in item['description']:
                            print ('Access token invalid... Attempting to Renew Token...')
                            results=AccessToken(server,headers,username,password)
                            headers['X-auth-access-token']=results[0]
                        else:
                            print (f'Error in connection --> {traceback.format_exc()}')
                            outfile.write(f'Error occurred in GET --> {r.text}\n{url}\n')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')
        outfile.write(f'Error occurred in GET --> {r.text}\n{url}\n')

    IPS = input('Would You Like To Assign Intrusion Policy To Rules? [y/N]: ').lower()

    if IPS in (['yes','ye','y']):
        Test = False
        while not Test:
            # Request UUID for Intrusion Policy
            IPSUUID = input('Please enter Intrusion Policy UUID: ').lower().strip()
            # Verify UUID with RegEx match
            if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', IPSUUID):
                Test = True
            else:
                print('Invalid UUID....')
        # Request Intrusion Policy Name
        IPSNAME = input('Please enter Intrusion Policy Name exactly as seen in API: ')

        Test = False
        while not Test:
            # Request UUID for Variable Set
            VSETUUID = input('Please enter Varable Set UUID: ').lower()
            # Verify UUID with RegEx match
            if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', VSETUUID):
                Test = True
            else:
                print('Invalid UUID....')
        # Request Variable Set Name
        VSETNAME = input('Please enter Variable Set Name exactly as seen in API: ')

    FILEPOLICY = input('Would You Like To Assign File Policy To Rules? [y/N]: ').lower().strip()

    if FILEPOLICY in (['yes','ye','y']):
        Test = False
        while not Test:
            # Request UUID for File Policy
            FILEUUID = input('Please enter File Policy UUID: ').lower().strip()
            # Verify UUID with RegEx match
            if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', FILEUUID):
                Test = True
            else:
                print('Invalid UUID. Exiting...')
        # Request File Policy Name
        FILENAME = input('Please enter File Policy Name exactly as seen in API: ')

    # Random Generated JSON Output File
    filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
    filename += '.json'
    print(f'*\n*\nRANDOM LOG FILE CREATED... {filename}\n')

    # For Loop to parse data from raw JSON
    for item in ACP_DATA['items']:
        if item ['action'] == 'ALLOW':
            if IPS in (['yes','ye','y']):
                # Create IPS Policy
                item ['ipsPolicy'] = {}
                # Assign Values
                item ['ipsPolicy']['id'] = IPSUUID
                item ['ipsPolicy']['name'] = IPSNAME
                item ['ipsPolicy']['type'] = 'IntrusionPolicy'
                # Create VariableSet
                item ['variableSet'] = {}
                # Assign Values
                item ['variableSet']['id'] = VSETUUID
                item ['variableSet']['name'] = VSETNAME
                item ['variableSet']['type'] = 'VariableSet'
            if FILEPOLICY in (['yes','ye','y']):
                # Create FilePolicy
                item ['filePolicy'] = {}
                # Assign Values
                item ['filePolicy']['id'] = FILEUUID
                item ['filePolicy']['name'] = FILENAME
                item ['filePolicy']['type'] = 'FilePolicy'

            # Delete Unprocessable items
            del item['links']
            del item['metadata']

            # Create Comment List if not in item, to be able to delete
            item ['commentHistoryList'] = {}
            del item['commentHistoryList']

    try:
        put_data = ACP_DATA['items']
        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/policy/accesspolicies/{ACP_UUID}/accessrules?bulk=true'
        # REST call with SSL verification turned off:
        r = requests.put(url, json=put_data, headers=headers, verify=False)
        print(f'Performing API PUT to: {url}')
        status_code = r.status_code
        json_resp = r.json()
        if status_code == 200:
            print(f'Items Processing... View Output File For Full Change Log... {filename}')
            with open(filename, 'a') as OutFile:
                OutFile.write(json.dumps(json_resp,indent=4))
        else:
            print(f'Status code:--> {status_code}')
            print(f'Error occurred in PUT --> {json_resp}')
            r.raise_for_status()
    except requests.exceptions.HTTPError:
        err_resp = r.json()
        for item in err_resp['error']['messages']:
            # Error Handling for Access Token Timeout
            if 'Access token invalid' in item['description']:
                print ('Access token invalid... Attempting to Renew Token...')
                results=AccessToken(server,headers,username,password)
                headers['X-auth-access-token']=results[0]
                try:

                    # REST call with SSL verification turned off:
                    r = requests.put(url, json=put_data, headers=headers, verify=False)
                    print(f'Performing API PUT to: {url}')
                    status_code = r.status_code
                    json_resp = r.json()
                    if (status_code == 200):
                        print(f'Items Processing... View Output File For Full Change Log... {filename}')
                        with open(filename, 'a') as OutFile:
                            OutFile.write(json.dumps(json_resp,indent=4))
                    else:
                        print(f'Status code:--> {status_code}')
                        print(f'Error occurred in PUT --> {json.dumps(json_resp,indent=4)}')
                        r.raise_for_status()


                except requests.exceptions.HTTPError:
                    print (f'Error in connection --> {traceback.format_exc()}')

            else:
                print (f'Error in connection --> {traceback.format_exc()}')
    # End
    finally:
        if r: r.close()





#
#
#
# Define Inventory List Script as Funtion
def GetInventory(server,headers,username,password):
    print ('''
***********************************************************************************************
*                           Pull Full FMC Device Inventory List                               *
*_____________________________________________________________________________________________*
*                                                                                             *
***********************************************************************************************
''')

    print('Generating Access Token')
    # Generate Access Token and pull domains from auth headers
    results=AccessToken(server,headers,username,password)
    headers['X-auth-access-token']=results[0]
    domains = results[1]

    Test = False
    if len(domains) > 1:
        while not Test:
            print('Multiple FMC domains found:')
            for domain in domains:
                print(f'    {domain["name"]}')
            choice = input('\nPlease select an FMC domain: ').strip()
            for domain in domains:
                if choice in domain['name']:
                    API_UUID = domain['uuid']
                    Test=True
            if not Test:
                print('Invalid Selection...\n')
    else:
        API_UUID = domains[0]['uuid']

        ## Request API URI Path
        #API_UUID = input('Please Enter FMC Domain UUID: ').lower().strip()
        #if re.match('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', API_UUID):
        #    Test=True
        #else:
        #    print('Invalid UUID...')

    # Create Get DATA JSON Dictionary to collect data from GET calls
    print('*\n*\nCOLLECTING ALL INVENTORY...')
    try:
        # REST call with SSL verification turned off
        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/devices/devicerecords?offset=0&limit=1000&expanded=true'
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        print(f'1 - Status code is: {status_code}')
        DEVICELIST_DATA = r.json()
        json_resp = r.json()
        #print(f'Json: {json_resp}')
        if status_code == 200:
            while 'next' in json_resp['paging']:
                url_get = json_resp['paging']['next'][0]
                print(f'*\n*\nCOLLECTING NEXT INVENTORY PAGE... {url_get}')
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    print(f'2 - Status code is: {status_code}')
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            DEVICELIST_DATA['items'].append(item)
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')

    # Create Get DATA JSON Dictionary to collect data from GET calls
    print('*\n*\nCOLLECTING CLUSTER INVENTORY...')
    try:
        # REST call with SSL verification turned off
        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/deviceclusters/ftddevicecluster?offset=0&limit=1000&expanded=true'
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        print(f'Status code is: {status_code}')
        CLUSTER_DATA = r.json()
        json_resp = r.json()
        if status_code == 200:
            while 'next' in json_resp['paging']:
                url_get = json_resp['paging']['next'][0]
                print(f'*\n*\nCOLLECTING NEXT CLUSTER INVENTORY PAGE... {url_get}')
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    print(f'Status code is: {status_code}')
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            CLUSTER_DATA['items'].append(item)
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')

    # Create Get DATA JSON Dictionary to collect data from GET calls
    print('*\n*\nCOLLECTING HA PAIR INVENTORY...')
    try:
        # REST call with SSL verification turned off
        url = f'{server}/api/fmc_config/v1/domain/{API_UUID}/devicehapairs/ftddevicehapairs?offset=0&limit=1000&expanded=true'
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        print(f'Status code is: {status_code}')
        HA_DATA = r.json()
        json_resp = r.json()
        if status_code == 200:
            while 'next' in json_resp['paging']:
                url_get = json_resp['paging']['next'][0]
                print(f'*\n*\nCOLLECTING NEXT HA PAIR INVENTORY PAGE... {url_get}')
                try:
                    # REST call with SSL verification turned off
                    r = requests.get(url_get, headers=headers, verify=False)
                    status_code = r.status_code
                    print(f'Status code is: {status_code}')
                    json_resp = r.json()
                    if status_code == 200:
                        # Loop for First Page of Items
                        for item in json_resp['items']:
                            # Append Items to New Dictionary
                            HA_DATA['items'].append(item)
                except requests.exceptions.HTTPError as err:
                    print (f'Error in connection --> {err}')
    except requests.exceptions.HTTPError as err:
        print (f'Error in connection --> {err}')

    ## TEST PRINT
    #print(json.dumps(HA_DATA,indent=4))

    # Create Base Dict
    INVENTORY = {
        'deviceClusters':[],
        'deviceHAPairs':[],
        'devices':[]
        }

    if 'items' in CLUSTER_DATA:
        for item in CLUSTER_DATA['items']:
            temp_dict = {}
            temp_dict['name']= item['name']
            temp_dict['masterDevice'] = GetDeviceDetails(item['masterDevice']['id'],DEVICELIST_DATA['items'])
            temp_dict['slaveDevices'] = []
            for item in item['slaveDevices']:
                temp_dict['slaveDevices'].append(GetDeviceDetails(item['id'],DEVICELIST_DATA['items']))
            INVENTORY['deviceClusters'].append(temp_dict)

    if 'items' in HA_DATA:
        for item in HA_DATA['items']:
            temp_dict = {}
            temp_dict['name']= item['name']
            temp_dict['primary'] = GetDeviceDetails(item['primary']['id'],DEVICELIST_DATA['items'])
            temp_dict['secondary'] = GetDeviceDetails(item['secondary']['id'],DEVICELIST_DATA['items'])
            INVENTORY['deviceHAPairs'].append(temp_dict)

    if 'items' in DEVICELIST_DATA:
        for item in DEVICELIST_DATA['items']:
            temp_dict = {}
            temp_dict['name'] = item['name']
            temp_dict['model'] = item['model']
            temp_dict['hostname'] = item['hostName']
            temp_dict['healthStatus'] = item['healthStatus']
            temp_dict['sw_version'] = item['sw_version']
            temp_dict['license_caps'] = item['license_caps']
            temp_dict['ftdMode'] = item['ftdMode']
            temp_dict['deviceSerialNumber'] = item['metadata']['deviceSerialNumber']
            temp_dict['sru_version'] = item['metadata']['sruVersion']
            temp_dict['vdb_version'] = item['metadata']['vdbVersion']
            temp_dict['snort_version'] = item['metadata']['snortVersion']
            if 'chassisData' in item['metadata']: temp_dict['chassisData'] = item['metadata']['chassisData']
            INVENTORY['devices'].append(temp_dict)


    print('FMC Inventory compilation successful...')
    # Ask if JSON output should be saved to File
    save = input('Would You Like To Save The JSON Output To File? [y/N]: ').lower()
    if save in (['yes','ye','y']):
        # Random Generated JSON Output File
        filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
        filename += '.json'
        print(f'*\n*\nRANDOM OUTPUT FILE CREATED... {filename}\n')
        with open(filename, 'a') as OutFile:
            OutFile.write(json.dumps(INVENTORY,indent=4))
    elif save in (['no','n','']):
        print(json.dumps(INVENTORY,indent=4))

    # Ask if CSV output should be saved to File
    save = input('Would You Like To Save CSV Output To File? [y/N]: ').lower()
    if save in (['yes','ye','y']):
        # Random Generated CSV Output File
        filename = ''.join(i for i in [chr(random.randint(97,122)) for i in range(6)])
        filename += '.csv'
        print(f'*\n*\nRANDOM OUTPUT FILE CREATED... {filename}\n')
        with open(filename, 'a') as OutFile:
            OutFile.write('NAME,MODEL,HOSTNAME,VERSION,LICENSE,STATUS,CHASSIS_SERIAL,MODE,SRU,VDB,SNORT\n')
            if INVENTORY['deviceClusters'] != []:
                for item in INVENTORY['deviceClusters']:
                    serial = ''
                    name = item['masterDevice']['name']
                    model = item['masterDevice']['model']
                    version = item['masterDevice']['sw_version']
                    status = item['masterDevice']['healthStatus']
                    if 'chassisData' in item['masterDevice']: serial = item['masterDevice']['chassisData']['chassisSerialNo']
                    OutFile.write(f'{name},{model},{version},{status},{serial}\n')
                    for item in item['slaveDevices']:
                        serial = ''
                        name = item['name']
                        model = item['model']
                        version = item['sw_version']
                        status = item['healthStatus']
                        if 'chassisData' in item: serial = item['chassisData']['chassisSerialNo']
                        OutFile.write(f'{name},{model},{version},{status},{serial}\n')
            if INVENTORY['deviceHAPairs'] != []:
                for item in INVENTORY['deviceHAPairs']:
                    serial = ''
                    name = item['primary']['name']
                    model = item['primary']['model']
                    version = item['primary']['sw_version']
                    status = item['primary']['healthStatus']
                    if 'chassisData' in item['primary']: serial = item['primary']['chassisData']['chassisSerialNo']
                    OutFile.write(f'{name},{model},{version},{status},{serial}\n')
                    serial = ''
                    name = item['secondary']['name']
                    model = item['secondary']['model']
                    version = item['secondary']['sw_version']
                    status = item['secondary']['healthStatus']
                    if 'chassisData' in item['secondary']: serial = item['secondary']['chassisData']['chassisSerialNo']
                    OutFile.write(f'{name},{model},{version},{status},{serial}\n')
            if INVENTORY['devices'] != []:
                for item in INVENTORY['devices']:
                    serial = item['deviceSerialNumber']
                    name = item['name']
                    model = item['model']
                    hostname = item['hostname']
                    version = item['sw_version']
                    license = item['license_caps']  
                    status = item['healthStatus']
                    mode = item['ftdMode']
                    sru_version = item['sru_version']
                    vdb_version = item['vdb_version']
                    snort_version = item['snort_version']
                    if 'chassisData' in item: serial = item['chassisData']['chassisSerialNo']                   
                    str_license = listToString(license) # Grab the elements in the license object and conver to a string
                    OutFile.write(f'{name},{model},{hostname},{version},{str_license},{status},{serial},{mode},{sru_version},{vdb_version},{snort_version}\n')


#
#
#
# Run Script if main
if __name__ == "__main__":
    #
    #
    #
    # Initial input request
    print ('''
***********************************************************************************************
*                                                                                             *
*                   Cisco FMC v6 API Tools (Written for Python 3.6+)                          *
*                                                                                             *
***********************************************************************************************
*                                                                                             *
* USER INPUT NEEDED:                                                                          *
*                                                                                             *
*  1. FQDN for FMC server (hostname.domain.com)                                               *
*                                                                                             *
*  2. API Username                                                                            *
*                                                                                             *
*  3. API Password                                                                            *
*                                                                                             *
***********************************************************************************************
''')

    Test = False
    while not Test:
        # Request FMC server FQDN
        server = input('Please Enter FMC fqdn: ').lower().strip()

        # Validate FQDN
        if server[-1] == '/':
            server = server[:-1]
        if '//' in server:
            server = server.split('//')[-1]

        # Perform Test Connection To FQDN
        s = socket.socket()
        print(f'Attempting to connect to {server} on port 443')
        try:
            s.connect((server, 443))
            print(f'Connecton successful to {server} on port 443')
            Test = True
        except:
            print(f'Connection to {server} on port 443 failed: {traceback.format_exc()}\n\n')

    # Adding HTTPS to Server for URL
    server = f'https://{server}'
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}

    # Request Username and Password without showing password in clear text
    username = input('Please Enter API Username: ').strip()
    password = define_password()
    print ('''
***********************************************************************************************
*                                                                                             *
* TOOLS AVAILABLE:                                                                            *
*                                                                                             *
*  1. Basic URL GET                                                                           *
*                                                                                             *
*  2. Create Network-Objects in bulk (POST)                                                   *
*                                                                                             *
*  3. Create Network-Objects in bulk and add to New Object-Group (POST)                       *
*                                                                                             *
*  4. Update IPS and/or File Policy for Access Rules (PUT)                                    *
*                                                                                             *
*  5. Get Inventory List from FMC (GET)                                                       *
*                                                                                             *
***********************************************************************************************
''')

    #
    #
    #
    # Run script until user cancels
    while True:
        Script = False
        while not Script:
            script = input('Please Select Script: ')
            if script == '1':
                Script = True
                BlankGet(server,headers,username,password)
            elif script == '2':
                Script = True
                PostNetworkObject(server,headers,username,password)
            elif script == '3':
                Script = True
                PostNetworkObjectGroup(server,headers,username,password)
            elif script == '4':
                Script = True
                PutIntrusionFile(server,headers,username,password)
            elif script == '5':
                Script = True
                GetInventory(server,headers,username,password)
            else:
                print('INVALID ENTRY... ')

        # Ask to end the loop
        print ('''
***********************************************************************************************
*                                                                                             *
* TOOLS AVAILABLE:                                                                            *
*                                                                                             *
*  1. Basic URL GET                                                                           *
*                                                                                             *
*  2. Create Network-Objects in bulk (POST)                                                   *
*                                                                                             *
*  3. Create Network-Objects in bulk and add to New Object-Group (POST)                       *
*                                                                                             *
*  4. Update IPS and/or File Policy for Access Rules (PUT)                                    *
*                                                                                             *
*  5. Get Inventory List from FMC (GET)                                                       *
*                                                                                             *
***********************************************************************************************
''')
        Loop = input('*\n*\nWould You Like To use another tool? [y/N]').lower()
        if Loop not in (['yes','ye','y','1','2','3','4','5','6']):
            break
