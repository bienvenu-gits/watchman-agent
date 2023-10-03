import asyncio
from pysnmp.hlapi import *
import concurrent.futures


def get_one_sync(hostname, bind=None, community='public'):
    snmp_engine = SnmpEngine()
    iterator = cmdgen.getCmd(
        snmp_engine,
        CommunityData(community),
        UdpTransportTarget(hostname),
        ContextData(),
        # ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
        # ObjectType(ObjectIdentity('1.3.6.1.2.1.25.6.3.1.2'))
    )

    for errorIndication, errorStatus, errorIndex, varBinds in iterator:

        if errorIndication:
            print(errorIndication)
            pass

        elif errorStatus:
            print(errorStatus)
        else:
            for varBind in varBinds:
                print(' = '.join([x.prettyPrint() for x in varBind]))


async def main():
    hostnames = [('209.97.189.19', 161)]
    loop = asyncio.get_event_loop()

    # Use a ThreadPoolExecutor to run the synchronous function in a separate thread
    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = [loop.run_in_executor(executor, get_one_sync, host) for host in hostnames]

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
    import re

    # package_string = "zerofree_1.1.1-1build3_amd64"
    #
    # # Define the regular expression pattern to match the version format
    # pattern = r'\d+(\.\d+)*'
    #
    # # Use re.search to find the version in the string
    # match = re.search(pattern, package_string)
    #
    # if match:
    #     version = match.group()
    #     print(f"Version: {version}")
    # else:
    #     print("No version found in the string")

    # version_string = "1:1.2.11.dfsg-2ubuntu9.2"
    #
    # # Utilisez une expression régulière pour extraire les composants de la version
    # pattern = r'^(\d+:)?([^:]+)-([\d.]+)([\w.]*)$'
    # match = re.match(pattern, version_string)
    #
    # if match:
    #     epoch = match.group(1) if match.group(1) else "0"
    #     upstream_version = match.group(2)
    #     debian_revision = match.group(3)
    #     ubuntu_revision = match.group(4)
    #
    #     print(f"Epoch: {epoch}")
    #     print(f"Upstream Version: {upstream_version}")
    #     print(f"Debian Revision: {debian_revision}")
    #     print(f"Ubuntu Revision: {ubuntu_revision}")
    # else:
    #     print("Le format de la version n'est pas valide.")

    # from packaging import version as pkg_version
    #
    #
    # def clean_version_string(version_string):
    #     # Prétraitement : Remplacer le tilde par un signe plus (+)
    #     version_string = re.sub(r'~', '+', version_string)
    #     # Prétraitement : Retirer les caractères non alphanumériques
    #     version_string = re.sub(r'[^a-zA-Z0-9.+-]', '', version_string)
    #     return version_string
    #
    #
    # def parse_linux_version(version_string):
    #     # Nettoyer la chaîne de version
    #     version_string = clean_version_string(version_string)
    #
    #     try:
    #         version = pkg_version.parse(version_string)
    #         return {
    #             'original_version': version_string,
    #             'parsed_version': str(version),
    #         }
    #     except pkg_version.InvalidVersion:
    #         return None
    #
    #
    # # Exemple d'utilisation
    # version_strings = [
    #     "1.1.1-1build3_amd64",
    #     "1.8.21p2-3ubuntu1.4",
    #     "2.55.5+18.04",
    #     "2018.09.18.1~18.04.2",
    #     "7.6.q-27",
    #     "1.29b-2ubuntu0.3",
    #     "2.88dsf-59.10ubuntu1",
    # ]
    #
    # for version_string in version_strings:
    #     parsed_version = parse_linux_version(version_string)
    #     if parsed_version:
    #         print(f"Original Version: {parsed_version['original_version']}")
    #         print(f"Parsed Version: {parsed_version['parsed_version']}\n")
    #     else:
    #         print(f"Le format de la version n'est pas valide : {version_string}\n")

    from semver.version import Version


    def parse_linux_version(version_string):
        try:
            parsed_version = Version.parse(version_string)
            return {
                'original_version': version_string,
                'parsed_version': str(parsed_version),
            }
        except Exception as e:
            print(e)
            return None


    # Exemple d'utilisation
    version_strings = [
        "1.1.1-1build3",
        "1.8.21p2-3ubuntu1.4",
        "2.55.5+18.04",
        "2018.09.18.1~18.04.2",
        "7.6.q-27",
        "1.29b-2ubuntu0.3",
        "2.88dsf-59.10ubuntu1",
        "1.2.3"
    ]

    for version_string in version_strings:
        parsed_version = parse_linux_version(version_string)
        if parsed_version:
            print(f"Original Version: {parsed_version['original_version']}")
            print(f"Parsed Version: {parsed_version['parsed_version']}\n")
        else:
            print(f"Le format de la version n'est pas valide : {version_string}\n")
