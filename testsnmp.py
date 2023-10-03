# from pysnmp.entity.rfc3413.oneliner import cmdgen

# # Replace these with your SNMP community string and target host
# community_string = "public"
# target_host = "209.97.189.19"

# # OID for the desired SNMP table (1.3.6.1.2.1.25.6.3.1.2)
# oid = (1, 3, 6, 1, 2, 1, 25, 6, 3, 1, 2)

# # Create an SNMP command generator
# cmd_gen = cmdgen.CommandGenerator()


# # Perform the SNMP walk
# error_indication, error_status, error_index, var_bind_table = cmd_gen.nextCmd(
#     cmdgen.CommunityData(community_string),
#     cmdgen.UdpTransportTarget((target_host, 161)),
#     oid
# )

# # Check for errors
# if error_indication:
#     print(f"SNMP Walk failed: {error_indication}")
# else:
#     for var_bind_table_row in var_bind_table:
#         for name, val in var_bind_table_row:
#             print(f"{val.prettyPrint()}")


# community_string = "public"
# target_host = "209.97.189.19"

# # Create an SNMP command generator
# cmd_gen = cmdgen.CommandGenerator()

# # OID for the sysDescr.0 MIB object (1.3.6.1.2.1.1.1.0)
# oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)

# # Perform the SNMP GET operation
# error_indication, error_status, error_index, var_binds = cmd_gen.getCmd(
#     cmdgen.CommunityData(community_string),
#     cmdgen.UdpTransportTarget((target_host, 161)),
#     oid
# )

# # Check for errors
# if error_indication:
#     print(f"SNMP GET failed: {error_indication}")
# else:
#     for name, val in var_binds:
#         print(f"{name.prettyPrint()}: {val.prettyPrint()}")

# import re

# input_string = "Linux elaurichenickson 5.15.0-67-generic #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023 x86_64"

# # Define regex patterns for hostname, OS name, and version
# hostname_pattern = r'(\S+)'
# os_name_pattern = r'(\w+)'
# version_pattern = r'(\d+\.\d+\.\d+-\S+)'

# # Use regex to extract the values
# hostname_match = re.search(hostname_pattern, input_string)
# os_name_match = re.search(os_name_pattern, input_string)
# version_match = re.search(version_pattern, input_string)

# # Check if matches were found and print the results
# if hostname_match:
#     hostname = hostname_match.group(1)
#     print("Hostname:", hostname)

# if os_name_match:
#     os_name = os_name_match.group(1)
#     print("OS Name:", os_name)

# if version_match:
#     version = version_match.group(1)
#     print("Version:", version)



# version = reformat_version(item[1])

# def reformat_version(version):
#     newformat = version
#     # Define a regex pattern to match the version (digits and dots)
#     pattern = r'(\d+(\.\d+)*)'

#     # Use re.search to find the first match in the input string
#     match = re.search(pattern, version)

#     # Check if a match was found
#     if match:
#         newformat = match.group(1)  # Extract the matched version
#         print("Version:", version)
#     else:
#         print("No version found in the input string.")
#     return newformat


# import re

# snmp_description = "SNMPv2-MIB::sysDescr.0: Linux elaurichenickson 5.15.0-67-generic #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023 x86_64"

# # Define regex patterns for hostname and OS name
# hostname_pattern = r'Linux\s+([^\s]+)'
# os_name_pattern = r'(\w+)\s+[\w.]+'

# # Use regex to extract the values
# hostname_match = re.search(hostname_pattern, snmp_description)
# os_name_match = re.search(os_name_pattern, snmp_description)

# # Check if matches were found and print the results
# if hostname_match:
#     hostname = hostname_match.group(1)
#     print("Hostname:", hostname)

# if os_name_match:
#     os_name = os_name_match.group(1)
#     print("OS Name:", os_name)


import subprocess

# Run the 'pkgutil --pkgs' command to get a list of installed packages
status, output = subprocess.getstatusoutput('pkgutil --pkgs')

if status == 0:
    # The command ran successfully, split the output into a list of package names
    installed_packages = output.splitlines()

    # Print package names and their versions
    for package in installed_packages:
        # Run 'pkgutil --pkg-info' to get package version
        status, package_info = subprocess.getstatusoutput(f'pkgutil --pkg-info {package}')
        if status == 0:
            # Extract the package version from the package_info string
            version_line = [line for line in package_info.splitlines() if line.startswith("version: ")]
            if version_line:
                package_version = version_line[0].replace("version: ", "")
                print(f"Package: {package}, Version: {package_version}")
            else:
                print(f"Package: {package}, Version: Not Found")
        else:
            print(f"Error retrieving package info for {package}: {package_info}")
else:
    # An error occurred
    print(f"Error running 'pkgutil --pkgs': {output}")


