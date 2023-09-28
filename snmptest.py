import asyncio
from pysnmp.hlapi import *
import concurrent.futures


def get_one_sync(hostname, bind=None, community='public'):
    snmp_engine = SnmpEngine()
    iterator = getCmd(
        snmp_engine,
        CommunityData(community),
        UdpTransportTarget(hostname),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
        # ObjectType(ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.host.hrSWInstalled.hrSWInstalledTable'
        #                           '.hrSWInstalledEntry.hrSWInstalledName.0'))
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.6.3.1.2'))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        pass

    elif errorStatus:
        pass
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


async def main():
    hostnames = [('demo.pysnmp.com', 161)]
    loop = asyncio.get_event_loop()

    # Use a ThreadPoolExecutor to run the synchronous function in a separate thread
    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = [loop.run_in_executor(executor, get_one_sync, host) for host in hostnames]

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
