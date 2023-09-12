from pysnmp.hlapi import *

# Configuration SNMP de l'appareil à gérer
target_host = 'demo.pysnmp.com'
security_username = 'usr-sha-aes128'
auth_protocol = usmHMACSHAAuthProtocol  # Utilisez usmHMACSHAAuthProtocol pour SHA
auth_password = 'authKey1'
privacy_protocol = usmAesCfb128Protocol  # Utilisez usmAesCfb128Protocol pour AES
privacy_password = 'privKey1'
port = 161

# OID pour l'information que vous souhaitez récupérer
oid = '1.3.6.1.2.1.1.1.0'

# Créer une session SNMPv3
snmp_object = ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
get_data = getCmd(SnmpEngine(),
                  CommunityData('public', mpModel=0),
                  UsmUserData(userName=security_username, authProtocol=auth_protocol, authKey=auth_password,
                              privKey=privacy_password, privProtocol=privacy_protocol),
                  UdpTransportTarget((target_host, port)),
                  ContextData(),
                  snmp_object)

# Récupérer les informations SNMP
error_indication, error_status, error_index, var_binds = next(get_data)

if error_indication:
    print(f"Erreur : {error_indication}")
else:
    if error_status:
        print(f"Erreur : {error_status.prettyPrint()} à l'index {error_index}")
    else:
        for var_bind in var_binds:
            print(f"{var_bind[0]} = {var_bind[1]}")

# Vous pouvez répéter ces étapes pour récupérer d'autres informations SNMP
