***Cisco FMC v6.7 API Tools (Written for Python 3.6+)***

**TOOLS AVAILABLE**
1. Basic URL GET
2. Create Network-Objects in bulk (POST)
3. Create Network-Objects in bulk and add to New Object-Group (POST)
4. Update IPS and/or File Policy for Access Rules (PUT)
5. Get Inventory List from FMC (GET)
6. Register FTD to FMC
7. Migrate Prefilter rules to Access Rules


_____________________________________________________________________________________________
**Basic URL GET Script**

USER INPUT NEEDED:
1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/{object_UUID})
2. Expand output to show details of each object *(Not Supported with {object_UUID} GET)
3. Limit output to a specific number of objects *(Not Supported with {object_UUID} GET)
4. Save output to JSON file


_____________________________________________________________________________________________
**Create Network Objects in bulk**

USER INPUT NEEDED:
1. Select Object type

2. CSV Data Input file
  * CSV FORMAT:
    * No Header Row & comma delimited
    * Can contain Host, Range, Network or FQDN objects, not a combination
    * Column0 = ObjectName
    * Column1 = Address


_____________________________________________________________________________________________
**Create Network Objects in bulk and add to new Object-Group**

USER INPUT NEEDED:
1. TXT Data Input file (ASA "show run object-group" output)


_____________________________________________________________________________________________
**Update IPS and/or File Policy for Access Rules**

USER INPUT NEEDED:
1. Select Access Policy
2. Select Intrusion Policy and Variable Set to apply to ALL rules
3. Select File Policy to apply to ALL rules

_____________________________________________________________________________________________
**Get Inventory List from FMC**

USER INPUT NEEDED:
1. Save output to JSON or CSV file

_____________________________________________________________________________________________
**Update IPS and/or File Policy for Access Rules**

USER INPUT NEEDED:
1. FTD IP address
2. FTD display name
3. FTD CLI username and password
4. Select ACP to apply to FTD

_____________________________________________________________________________________________
**Update IPS and/or File Policy for Access Rules**

USER INPUT NEEDED:
1. Select Access Policy
2. Select Intrusion Policy and Variable Set to apply to ALL converted rules
3. Select File Policy to apply to ALL converted rules

