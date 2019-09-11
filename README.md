TOOLS AVAILABLE:
1. Blank URL GET
2. Create Network-Objects in bulk (POST)
3. Create Network-Objects in bulk and add to New Object-Group (POST)
4. Update IPS and/or File Policy for Access Rules (PUT)


_____________________________________________________________________________________________
Blank URL GET Script:
USER INPUT NEEDED:
1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/{object_UUID})
2. Expand output to show details of each object *(Not Supported with {object_UUID} GET)
3. Limit output to a specific number of objects *(Not Supported with {object_UUID} GET)
4. Save output to JSON file


_____________________________________________________________________________________________
Create Network Objects in bulk
USER INPUT NEEDED:
1. URI Path (/api/fmc_config/v1/domain/{domain_UUID}/object/networks/)
2. CSV Data Input file (CSV FORMAT - No Header Row: Column0 = ObjectName, Column1 = Address)
3. Output Log File to JSON file


_____________________________________________________________________________________________
Create Network Objects in bulk and add to new Object-Group
USER INPUT NEEDED:
1. FMC Domain UUID (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/)
2. TXT Data Input file (ASA "show run object-group" output)
3. Output Log File to JSON file


_____________________________________________________________________________________________
Update IPS and/or File Policy for Access Rules
USER INPUT NEEDED:
1. FMC Domain UUID (/api/fmc_config/v1/domain/{domain_UUID}/object/networkgroups/)
2. Access Policy UUID (/api/fmc_config/v1/domain/{domain_UUID}/policy/accesspolicies/{ACP_UUID})
3. Intrusion Policy (Yes/No)
4. File Policy (Yes/No)
5. Output Log File
