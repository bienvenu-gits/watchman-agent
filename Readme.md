Watchman Agent Documentation
Table of Contents
Overview
Network Configuration
Connect Configuration
Export Configuration
Run Command
1. Overview
Watchman Agent is a versatile application designed to configure and manage various settings for network and stack monitoring. This documentation provides a comprehensive guide on how to use the application and its different configuration options.
2. Network Configuration 
The network command allows users to save network-related configuration variables. Below are the available options:
-t, --network-target: The network target IP address. (Type: IP Address, Required: False)
-m, --cidr: The mask in CIDR annotation. Default is set to 24. Example: --cidr 24 (Type: Integer, Required: True)
-c, --snmp-community: SNMP community used for authenticating the SNMP management station. Default is set to 'public'. (Type: String, Required: True)
-p, --snmp-port: SNMP port on which clients listen. Default is set to 161. (Type: Integer, Required: True)
-u, --snmp-user: SNMP authentication user. (Type: String, Required: False)
-a, --snmp-auth-key: SNMP authentication key. (Type: String, Required: False)
-s, --snmp-priv-key: SNMP private key. (Type: String, Required: False)
-e, --exempt: Device list to ignore when getting stacks. Example: --exempt 192.168.1.12 (Type: String, Required: False)
3. Connect Configuration 
The connect command is used to save connection-related configuration variables. Below are the available options:
-m, --mode: Runtime mode for agent execution (network or agent). Default is set to agent. (Type: String, Required: False)
-c, --client-id: Client ID for authentication purposes. (Type: String, Required: True)
-s, --client-secret: Client Secret for authentication purposes. (Type: String, Required: True)
4. Export Configuration 
The export command is used to save exportation-related configuration variables. Below are the available options:
-a, --activate: Activate exportation run mode. Default is False if the option is not set. (Type: Boolean, Required: False)
-p, --path: The path to the export directory. Default is the current user's home directory. (Type: Path, Required: False)
-f, --file-name: The exportation file name. Default is set to watchman_export_assets.csv. (Type: String, Required: False)
5. Run Command 
The run command attaches monitoring to a cron job and watches for stacks.
To execute the run command, use:
$ watchman_agent run
This command will initiate monitoring and execute the configured actions based on the set parameters.