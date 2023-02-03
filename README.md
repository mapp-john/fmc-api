# ***Cisco FMC v6.7 API Tools (Written for Python 3.6+)***
[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/mapp-john/fmc-api)

## **Installation**
1. Clone project repository or download ZIP and extract
2. Install required python packages using `pip3 install -r requirements.txt`

## **Usage**
```
> python3 fmc_api_tools.py


***********************************************************************************************
*                                                                                             *
*                   Cisco FMC 6.7+ API Tools (Written for Python 3.6+)                        *
*                                                                                             *
***********************************************************************************************

***********************************************************************************************
*                                                                                             *
* TOOLS AVAILABLE:                                                                            *
*                                                                                             *
*  1. Basic URL GET                                                                           *
*                                                                                             *
*  2. Create Network-Objects in bulk                                                          *
*                                                                                             *
*  3. Create Network-Objects in bulk and add to New Object-Group                              *
*                                                                                             *
*  4. Update IPS and/or File Policy for Access Rules                                          *
*                                                                                             *
*  5. Get Inventory List from FMC                                                             *
*                                                                                             *
*  6. Register FTD to FMC                                                                     *
*                                                                                             *
*  7. Deploy Pending FTDs                                                                     *
*                                                                                             *
*  8. Migrate Prefilter rules to Access Rules                                                 *
*                                                                                             *
*  9. Update Object Group with entries from txt file                                          *
*                                                                                             *
*  10. Export ACP and Prefilter Rules to CSV file                                             *
*                                                                                             *
*  11. Download Snort.org Rules                                                               *
*                                                                                             *
*  12. Delete FTDs from FMC using Name or Model search                                        *
*                                                                                             *
*  13. Edit manager config for FTDs in bulk                                                   *
*                                                                                             *
***********************************************************************************************

Please Select Tool:
```

## **TOOLS AVAILABLE**
1. Basic URL GET
2. Create Network-Objects in bulk
3. Create Network Objects and Object Groups in bulk
4. Update IPS and/or File Policy for Access Rules
5. Get Inventory List from FMC
6. Register FTD to FMC
7. Deploy Pending FTDs
8. Migrate Prefilter rules to Access Rules
9. Update Object Group with entries from txt file
10. Export ACP and Prefilter Rules to CSV file
11. Download Snort.org Rules
12. Delete FTDs from FMC using Name or Model search
13. Edit manager config for FTDs in bulk

_____________________________________________________________________________________________
### **Basic URL GET Script**

USER INPUT NEEDED:
1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/{object_UUID})
2. Expand output to show details of each object *(Not Supported with {object_UUID} GET)
3. Limit output to a specific number of objects *(Not Supported with {object_UUID} GET)
4. Save output to JSON file

_____________________________________________________________________________________________
### **Create Network Objects in bulk**

USER INPUT NEEDED:
1. Select Object type

2. CSV Data Input file
  * CSV FORMAT:
    * No Header Row & comma delimited
    * Can contain Host, Range, Network or FQDN objects, not a combination
    * Column0 = ObjectName
    * Column1 = Address

_____________________________________________________________________________________________
### **Create Network Objects and Object Groups in bulk**

USER INPUT NEEDED:
1. TXT Data Input file
    * Output from ASA "show run object network" AND "show run object-group network"
    * Ensure no object names overlap with existing objects
    * Ensure nested groups are above groups nesting them
##### Example TXT
```
object network Net-1
 subnet 10.1.1.0 255.255.255.0
object network Host-1
 host 10.1.1.1
object network FQDN-1
 fqdn www.google.com
object network Range-1
 range 10.1.1.1 10.1.1.255
object-group network Group-1
 network-object host 10.1.1.1
 network-object 10.2.2.0 255.255.255.0
object-group network Group-2
 network-object object Net-1
 network-object object Host-1
 network-object object FQDN-1
 network-object object Range-1
 group-object Group-1
```

_____________________________________________________________________________________________
### **Update IPS and/or File Policy for Access Rules**

USER INPUT NEEDED:
1. Select Access Policy
2. Apply IPS and File Policy to ALL rules? [y/N]
    * Selecting `NO` will apply changes only to rules which currently have IPS/File policy applied
3. Select Intrusion Policy and Variable Set
    * Selecting `None` will NOT remove currently applied policy
4. Select File Policy
    * Selecting `None` will NOT remove currently applied policy

_____________________________________________________________________________________________
### **Get Inventory List from FMC**

USER INPUT NEEDED:
1. Save output to JSON or CSV file

_____________________________________________________________________________________________
### **Register FTD to FMC**

USER INPUT NEEDED:
1. FTD IP address
2. FTD display name
3. FTD CLI username and password
4. Select ACP to apply to FTD

_____________________________________________________________________________________________
### **Deploy Pending FTDs**

USER INPUT NEEDED:
1. Deploy FTDs with Traffic Interruption? [y/N]

_____________________________________________________________________________________________
### **Migrate Prefilter rules to Access Rules**

USER INPUT NEEDED:
1. Select Access Policy
2. Select Intrusion Policy and Variable Set to apply to ALL converted rules
3. Select File Policy to apply to ALL converted rules

_____________________________________________________________________________________________
### **Update Object Group with entries from txt file**

USER INPUT NEEDED:
1. Object Group Name
2. TXT Data Input file
    * Supports groups with only IPv4 Host and Network objects
    * Text file must contain only host IPs and networks with CIDR notation
##### Example TXT
```
10.1.1.1
10.1.1.3
10.1.3.0/24
10.2.2.0/24
```

_____________________________________________________________________________________________
### **Export ACP and Prefilter Rules to CSV file**

Automatically saves CSV file to local directory


_____________________________________________________________________________________________
### **Download Snort.org Rules**

Automatically downloads base rules from Snort.org and modifies SID to be imported into FMC

_____________________________________________________________________________________________
### **Update Object Group with entries from txt file**

USER INPUT NEEDED:
1. Search for FTD by name
2. Search for FTD by model
3. Verify FTDs to be deleted

_____________________________________________________________________________________________
### **Update Object Group with entries from txt file**

USER INPUT NEEDED:
1. Primary FMC UUID to edit (obtain from FMC CLI "show version")
2. New IP address for Primary FMC
3. Secondary FMC UUID to edit (obtain from FMC CLI "show version")
4. New IP address for Secondary FMC
5. CSV File for FTD SSH details
  * CSV FORMAT:
    * No Header Row & comma delimited
    * Column0 = ftd_hostname
    * Column1 = ssh_port
    * Column2 = ftd_user
    * Column3 = ftd_pass

6. Comma separated list of FTD hostnames or IPs (IE. "1.1.1.1, 2.2.2.2, 3.3.3.3")
7. FTD SSH port, if not default
8. Username and Password for FTD SSH

##### Example CSV
```
ftd1.cisco.com,2200,admin,cisco123
ftd2.cisco.com,2201,admin,cisco123
ftd3.cisco.com,2202,admin,cisco123
```



