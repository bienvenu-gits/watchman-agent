import ipaddress
import json
import nmap
import paramiko
import platform as pt
import re
import schedule
import socket
import subprocess
import time
import yaml
from pathlib import Path

import click
import keyring
import requests
from environs import Env
from keyring.errors import NoKeyringError
from pysnmp.hlapi import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from sqlitedict import SqliteDict

"""
    Fetch Variables environment
"""
env = Env()
env.read_env()
ENV = env("ENV_MODE")

WEBHOOK_URL = env("WEBHOOK_URL")
CONNECT_URL = env("CONNECT_URL")

if ENV == "development":
    WEBHOOK_URL = env("DEV_WEBHOOK_URL")
    CONNECT_URL = env("DEV_CONNECT_URL")

hour_range_value = 24


class KeyDB(object):
    def __init__(self, table_name, db, mode="read"):
        self.__db_object = None
        self._table_name = table_name
        self._db = db
        self._mode = mode

    def __enter__(self):
        if self._mode == "read":
            self.__db_object = SqliteDict(self._db, tablename=self._table_name, encode=json.dumps, decode=json.loads)

        if self._mode == "write":
            self.__db_object = SqliteDict(self._db, tablename=self._table_name, encode=json.dumps, decode=json.loads,
                                          autocommit=True)
        return self

    def read_value(self, key: str):
        if key:
            return self.__db_object[key]
        return None

    def insert_value(self, key: str, value: str):
        if key and value and self._mode == "write":
            self.__db_object[key] = value
            return True
        return False

    def __exit__(self, type, val, tb):
        self.__db_object.close()


class IpType(click.ParamType):
    name = "ip"

    def convert(self, value, param, ctx):
        try:
            ip = ipaddress.ip_network(value)
        except:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError as e:
                print('failed')
                self.fail(
                    str(e),
                    param,
                    ctx,
                )
        return value


def custom_exit(message: str):
    raise SystemExit(message)


"""
    Network Host Scanning
"""


def get_network_hosts(target_hosts):
    active_hosts = []

    packets_for_each_host = [packet for packet in IP(dst=[target_hosts]) / ICMP()]

    for packet in packets_for_each_host:
        try:
            answer = sr1(packet, timeout=1)
            try:
                active_hosts.append(answer[IP].src)
            except:
                pass
        except OSError:
            custom_exit("You must run as administrator")

    return active_hosts


"""
    Host Query by snmp
"""


def getting_stacks_by_host_snmp(active_hosts, community):
    hosts_report = []
    for host in active_hosts:
        stacks = []
        command_output = subprocess.getstatusoutput("snmpwalk -v1 -c %s %s 1.3.6.1.2.1.25.6.3.1.2" % (community, host))
        if command_output[0] == 0:
            mibs = command_output[1].split('\n')
            for mib in mibs:
                try:
                    stack = mib.split('"')[1]
                    versions_info = stack.split("-")[-2:]
                    stack_names = stack.split("-")[:-2]
                except:
                    pass
                try:
                    if versions_info[0][0].isdigit():
                        stacks.append({
                            "name": "-".join(stack_names),
                            "version": "-".join(versions_info)
                        })
                    elif versions_info[1][0].isdigit():
                        stacks.append({
                            "name": "-".join(stack_names, versions_info[0]),
                            "version": versions_info[1]
                        })
                    else:
                        stacks.append({
                            "name": stack,
                            "version": stack
                        })

                except:
                    pass

        command_output = subprocess.getstatusoutput("snmpwalk -v1 -c %s %s .1.3.6.1.2.1.1.1.0" % (community, host))

        try:
            os_info = re.search('"(.*)"', command_output[1])
            if os_info is not None:
                os_info = os_info.group(1)
            else:
                os_info = command_output[1].split("#")[0]

        except:
            os_info = command_output[1].split("#")[0]

        if len(os_info) >= 50:
            os_info = os_info.split("#")[0]

        hosts_report.append({
            "os": os_info,
            "ipv4": host,
            "packages": stacks
        })

    return hosts_report


"""
    Display an error message
"""


def request_error(error):
    click.echo(error)
    custom_exit(
        """
            Unable to join the server !
            Try one of the following solutions:
            \t- Try later
            \t- Verify your network connection
            Contact support at support@watchman.bj, if the problem persists.\n
        """
    )


"""
    Get each container Name and image  
"""


def get_container_name_and_images():
    containers_info = {}

    try:
        command_output = subprocess.run(
            ["docker", "ps"], stdout=subprocess.PIPE, capture_output=True, text=True)
        command_output = command_output.stdout

        containers_general_data = command_output.split('\n')
        containers_general_data.pop(0)

        for el in containers_general_data:
            if el != '':
                tab = el.split(' ')
                if "alpine" in tab[3] or "ubuntu" in tab[3] or "debian" in tab[3] or "rehl" in tab[3] or "centos" in \
                        tab[3]:
                    containers_info[tab[-1]] = tab[3]
    except:
        pass

    return containers_info


"""
    Get packages and version result from command line
"""


def get_host_packages(command, host_os, file, container):
    if host_os == 'Windows':

        command_output = subprocess.check_output(command, text=True)

        output_list = command_output.split('\n')

        packages_versions = []

        for el in output_list:

            el = el.split()

            el = [i for i in el if i != '']  # purge space

            try:

                if el[-1][0].isdigit() and el[-1][-1].isdigit():
                    p_v = {
                        "name": " ".join(el[:-1]),
                        "version": el[-1]
                    }
                    if p_v["name"] != "":
                        packages_versions.append(p_v)

            except:
                pass
    elif host_os == "macOS":
        command_output = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        packages_versions = format_pkg_version(command_output, host_os)

    else:
        command_output = subprocess.Popen(command, stdout=subprocess.PIPE)
        packages_versions = format_pkg_version(command_output, host_os)
    if container is None:
        file.writelines([
            "\"os\" : \"%s\" , " % host_os,
            "\"packages\" : %s ," % packages_versions,
            "\"containers\" : [ "
        ])
        click.echo("\n\n + Listing Packages for %s successfully !!!\n" % host_os)
    else:

        file.writelines([

            " { "
            " \"name\" : \"%s\" ," % container,
            " \"packages\" : %s " % packages_versions,
            " } "

        ])

        click.echo(f" + Listing Packages for {container} container in {host_os} successfully !!!\n")


"""
    Get the host os 
"""


def get_host_os():
    if pt.system() == 'Windows':
        return 'Windows'
    elif pt.system() == 'Darwin':
        command_output = subprocess.run(["sw_vers"], stdout=subprocess.PIPE)
        command_output_lines = command_output.stdout.decode("utf-8").split('\n')
        mac = re.search("macOS", str(command_output_lines))
        if mac:
            return "macOS"
        else:
            print("ProductName not found in the input data.")

    command_output = subprocess.run(["hostnamectl"], stdout=subprocess.PIPE)
    command_output_lines = command_output.stdout.decode("utf-8").split('\n')

    for line in command_output_lines:
        if "system" in line.lower():
            return line.split(':')[-1].lower().lstrip()


"""
    Format the package name and version for usage 
"""


def format_pkg_version(command1_output, host_os):
    if "ubuntu" in host_os or "debian" in host_os:
        output = subprocess.check_output(
            ["awk", "$1 == 'ii' {print $2, $3}", "OFS=^^"], stdin=command1_output.stdout)
    elif "alpine" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1}"], stdin=command1_output.stdout)
    elif "centos" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1,$2}", "OFS=^^"], stdin=command1_output.stdout)
    elif "macOS" in host_os:
        output = subprocess.check_output(
            ["cut", "-d", "\t", "-f", "1,2"], stdin=command1_output.stdout)

    command1_output.wait()

    pkg_versions = output.decode("utf-8").split("\n")

    tab = []

    if host_os.split(' ')[0] in ["ubuntu", "debian", "centos"]:
        for pkg_version in pkg_versions:
            try:
                p_v = pkg_version.split('^^')

                if p_v[1][0].isdigit():
                    tab.append({
                        "name": p_v[0],
                        "version": p_v[1]
                    })
            except:
                pass

    elif "alpine" in host_os:

        for pkg_version in pkg_versions:

            try:

                pkg_version = pkg_version.split(" - ")[0]
                p_v = pkg_version.split("-")

                name = "-".join(p_v[:-2])
                version = "-".join(p_v[-2:])

                tab.append({
                    "name": name,
                    "version": version
                })

            except:
                pass

    return tab


"""
    Collect package name and version from command line
"""


def network_host_audit(file):
    host_os = get_host_os()

    if host_os == 'Windows':
        get_host_packages(
            ["powershell", "-Command", "Get-Package", "|", "Select", "Name,Version"], host_os, file, None)
    elif host_os == "macOS":
        get_host_packages(["brew", "list", "--versions"],
                          host_os, file, None)
    else:
        if "alpine" in host_os:
            get_host_packages(["apk", "info", "-vv"], host_os, file, None)
        elif "ubuntu" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "debian" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "rehl" in host_os:
            get_host_packages(["rpm", "-qa"], host_os, file, None)
        elif "centos" in host_os:
            get_host_packages(["yum", "list", "installed"],
                              host_os, file, None)
        else:
            custom_exit("Sorry, this Operating System is not supported yet.\n")
    #########
    ##
    # start container inspection
    ##
    ########

    containers_info = get_container_name_and_images()

    if len(containers_info):
        # get the key of the last container
        last_container = list(containers_info.keys())[-1]

    for container, image in containers_info.items():

        if "alpine" in image:
            get_host_packages(["docker", "exec", container,
                               "apk", "info", "-vv"], "alpine", file, container)
            # write a comma after the closed bracket only if it is not the last object to write
            if container != last_container:
                file.write(",")

        elif "ubuntu" in image:
            get_host_packages(["docker", "exec", container,
                               "dpkg", "-l"], "ubuntu", file, container)
            # write a comma after the closed bracket only if it is not the last object to write
            if container != last_container:
                file.write(",")

        elif "debian" in image:
            get_host_packages(["docker", "exec", container,
                               "dpkg", "-l"], "debian", file, container)
            # write a comma after the closed bracket only if it is not the last object to write
            if container != last_container:
                file.write(",")

        elif "rehl" in image:
            get_host_packages(["docker", "exec", container,
                               "rpm", "-qa"], "rehl", file, container)
            # write a comma after the closed bracket only if it is not the last object to write
            if container != last_container:
                file.write(",")

        elif "centos" in image:
            get_host_packages(["docker", "exec", container, "yum",
                               "list", "installed"], "centos", file, container)
            # write a comma after the closed bracket only if it is not the last object to write
            if container != last_container:
                file.write(",")


"""
    Format properly the content of the reported file to json syntax
"""


def format_json_report(client_id, client_secret, file):
    file_content = ""

    with open(file, "r+") as file_in_read_mode:
        file_content = file_in_read_mode.read()

    file_content = re.sub('\'', '"', file_content)

    with open(file, "w+") as file_in_write_mode:
        file_in_write_mode.write("")

    try:
        response = requests.post(
            url=WEBHOOK_URL,
            headers={
                "AGENT-ID": client_id,
                "AGENT-SECRET": client_secret
            },
            data={
                "data": file_content
            }
        )

        if response.status_code != 200:
            click.echo("\nExecution error️")
            click.echo("Message: ", response.json()["detail"])
    except requests.exceptions.RequestException as e:
        request_error(error=e)


def get_local_ip():
    try:
        # Create a socket object to retrieve the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)  # Set a timeout for the socket operation
        s.connect(("8.8.8.8", 80))  # Connect to a known external server
        local_ip = s.getsockname()[0]  # Get the local IP address
        s.close()
        return local_ip
    except Exception as e:
        return str(e)


def get_public_ip(host_address):
    try:
        # Use socket.gethostbyname to retrieve the IP address
        ip_address = socket.gethostbyname(host_address)
        print(f"ip_address {ip_address}")
        return ip_address
    except socket.gaierror as error:
        print(f"error {error}")
        return None


def get_remote_os_with_snmp(active_hosts):
    try:
        print(f"get_remote_os_with_snmp {active_hosts}")
        
        hosts_report = []
        # demo.pysnmp.com
        config = read_config()

        network_conf = config.get('network', {})

        network_snmp_conf = network_conf.get('snmp', {})

        # SNMPv3 credentials
        snmp_user = network_snmp_conf.get('user', None)
        snmp_auth_key = network_snmp_conf.get('auth_key', None)
        snmp_priv_key = network_snmp_conf.get('priv_key', None)
        snmp_engine_time = 12345  # Replace with the correct SNMP engine time
        snmp_engine_boots = 1  # Replace with the correct SNMP engine boots value

        # SNMPv3 engine ID (usually empty for most devices)

        target_port = network_snmp_conf.get('port', 161)  # Default SNMP port
        print(f"snmp_user {snmp_user}")
        print(f"snmp_auth_key {snmp_auth_key}")
        print(f"snmp_priv_key {snmp_priv_key}")

        # Create SNMPv3 security settings
        security_parameters = UsmUserData(
            snmp_user,
            snmp_auth_key,
            snmp_priv_key,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
            # securityEngineBoots=snmp_engine_boots,
            # securityEngineTime=snmp_engine_time
        )

        # Create SNMPv3 context
        context = ContextData()

        print(f"get_remote_os_with_snmp {active_hosts}")
        for host in active_hosts:

            print(f"host {host}")
            # SNMPv3 target
            target_host = get_public_ip(host)
            print(f"target_host {target_host}")
            print(f"security_parameters {security_parameters}")
            print(f"target_port {target_port}")
            print(f"context {context}")
            # Create SNMP request
            try:
                # get_request = getCmd(
                #     SnmpEngine(),
                #     security_parameters,
                #     UdpTransportTarget((target_host, target_port)),
                #     context,
                #     ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
                # )
                stacks = []
                command_output = subprocess.getstatusoutput(f"snmpget -v3  -l authPriv -u {snmp_user} -a SHA -A {snmp_auth_key} -x AES -X {snmp_priv_key} {host} 1.3.6.1.2.1.25.6.3.1.2")
                print(f"command_output {command_output}")
                if command_output[0] == 0:
                    print(f"command_output[0]")
                    mibs = command_output[1].split('\n')
                    print(f"mibs {mibs}")
                    for mib in mibs:
                        
                        print(f"mib {mib}")
                        try:
                            stack = mib.split('"')[1]
                            versions_info = stack.split("-")[-2:]
                            stack_names = stack.split("-")[:-2]
                        except:
                            pass
                        try:
                            if versions_info[0][0].isdigit():
                                stacks.append({
                                    "name": "-".join(stack_names),
                                    "version": "-".join(versions_info)
                                })
                            elif versions_info[1][0].isdigit():
                                stacks.append({
                                    "name": "-".join(stack_names, versions_info[0]),
                                    "version": versions_info[1]
                                })
                            else:
                                stacks.append({
                                    "name": stack,
                                    "version": stack
                                })

                        except:
                            pass
                        
                command_output = subprocess.getstatusoutput(f"snmpget -v3  -l authPriv -u {snmp_user} -a SHA -A {snmp_auth_key} -x AES -X {snmp_priv_key} {target_host} .1.3.6")
                try:
                    os_info = re.search('"(.*)"', command_output[1])
                    if os_info is not None:
                        os_info = os_info.group(1)
                    else:
                        os_info = command_output[1].split("#")[0]

                except:
                    os_info = command_output[1].split("#")[0]

                if len(os_info) >= 50:
                    os_info = os_info.split("#")[0]

                hosts_report.append({
                    "os": os_info,
                    "ipv4": host,
                    "packages": stacks
                })

                return hosts_report
                # get_request = getCmd(SnmpEngine(),
                #   CommunityData('public'),
                #   UdpTransportTarget(('demo.pysnmp.com', 161)),
                #   ContextData(),
                #   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
                # print(f"get_request {get_request}")
                # for i in get_request:
                #     print(f"i {i}")

                # # Execute SNMP request and print results
                # error_indication, error_status, error_index, var_binds = next(get_request)

                # if error_indication:
                #     print(f"Error: {error_indication}")
                # else:
                #     print("SNMP response:")
                #     for var_bind in var_binds:
                #         print(f"{var_bind[0]}\n{var_bind[1]}\n")
            except Exception as e:
                print(e)


    except Exception as e:
        return str(e)


def get_remote_os(ip_address, username, password):
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote machine
        ssh.connect(ip_address, username=username, password=password, timeout=5)

        # Run a command to retrieve OS information
        stdin, stdout, stderr = ssh.exec_command("uname -a")  # Linux-specific command
        os_info = stdout.read().decode().strip()

        # Close the SSH connection
        ssh.close()

        return os_info
    except Exception as e:
        return str(e)


def scan_snmp_ports(network_prefix, snmp_port):
    nm = nmap.PortScanner()
    scan_args = f"-p {snmp_port}"
    print(f"scan_args {scan_args}")

    # Perform the SNMP port scan on the specified network range
    nm.scan(hosts=f"{network_prefix}/24", arguments=scan_args)

    # Iterate through the scan results and print hosts with the SNMP port open
    if nm.all_hosts().items():
        for host, scan_result in nm.all_hosts().items():
            if snmp_port in scan_result['tcp']:
                print(f"Host: {host} - SNMP Port {snmp_port} is open")


def read_config():
    file_name = 'config.yml'
    with open(file_name, 'r') as config_file:
        loaded_config_data = yaml.safe_load(config_file)
    return loaded_config_data
    # if 'schedule' in loaded_config_data and 'hour_range' in loaded_config_data['schedule']:
    #     hour_range_value = loaded_config_data['schedule']['hour_range']


def update_config(file_name, loaded_config_data, new_key, new_value):
    loaded_config_data[new_key] = new_value
    # Write the updated data back to the YAML file
    with open(file_name, 'w') as config_file:
        yaml.dump(loaded_config_data, config_file)


def run_not_network(client_id, secret_key):
    """
        By cmd execution
    """
    with open("__", "w+") as file:
        # write the opening bracket of the json object
        file.writelines(["{"])

        file.writelines(["  \"%s\" : { " % pt.node(), ])

        network_host_audit(file)

        file.writelines([" ] } } "])

    file.close()
    format_json_report(client_id, secret_key, "__")


def run_network(community, device, client_id, secret_key):
    """
        By snmp mibs 
    """
    if community is None:
        custom_exit("Execution error: the snmp community is not specified.\n")
    else:
        print(f"RUN NETWORK")
        target_host = get_public_ip(device)
        # hosts = get_network_hosts(target_host)
        # print(f"hosts {hosts}")
        report = getting_stacks_by_host_snmp([target_host], community)
        # report = get_remote_os_with_snmp(['demo.pysnmp.com'])

        with open("___", "w+") as file:
            file.write("%s" % report)
        file.close()
        format_json_report(client_id, secret_key, "___")


@click.command()
@click.option('--network-mode', is_flag=True, help='Run in network mode')
@click.option("-c", "--community", type=str, default="public",
              help="SNMP community used to authenticate the SNMP management station.", required=0)
@click.option("-d", "--device", type=IpType(), help="The device ip address.")
@click.argument("client-id", type=str, required=0)
@click.argument("secret-key", type=str, required=0)
@click.argument("envfile", type=str, required=0)
def cli(network_mode, client_id, secret_key, community, device, envfile):
    config = read_config()

    schedule_conf = config.get('schedule', {})
    hour_range = schedule_conf.get('hours', 0.6)

    runtime_conf = config.get('runtime', {})
    mode = runtime_conf.get('mode', 'network' if network_mode else 'agent')
    client_id = runtime_conf.get('client_id', client_id)
    secret_key = runtime_conf.get('secret_key', secret_key)

    network_conf = config.get('network', {})
    community = network_conf.get('community', community)
    ip = network_conf.get('ip', device)

    try:
        response = requests.get(CONNECT_URL, headers={
            "AGENT-ID": client_id,
            "AGENT-SECRET": secret_key
        })

        if response.status_code == 200:
            token = response.json()["token"]
            if token:
                try:
                    # keyring may fail
                    keyring.set_password("watchmanAgent", "token", token)
                except NoKeyringError as e:
                    # use db method
                    with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "watchmanAgent.db",
                               mode="write") as obj:
                        obj.insert_value("token", token)
        else:
            click.echo("\nAuthentication failed!!")
            click.echo(f"Detail : {response.json()['detail']} ")
    except requests.exceptions.RequestException as e:
        request_error(error=e)
    try:
        if keyring.get_password("watchmanAgent", "token") is None:
            custom_exit("Authentication failed!!")
    except NoKeyringError as e:
        # use db method
        with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "watchmanAgent.db") as obj:
            if obj.read_value("token") is None:
                custom_exit("Authentication failed!!")
    """
        Getting stacks from the target 
    """
    if mode == 'agent':
        # schedule.every(hour_range).hours.do(run_not_network, client_id=client_id, secret_key=secret_key)
        run_not_network(client_id=client_id, secret_key=secret_key)
    else:
        run_network(community=community, device=ip, client_id=client_id, secret_key=secret_key)
        # schedule.every(hour_range).hours.do(run_network, community=community, device=ip, client_id=client_id, secret_key=secret_key)

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    cli()
