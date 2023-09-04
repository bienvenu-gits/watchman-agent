import ipaddress, json, subprocess, re, nmap
from pathlib import Path

import click
import keyring
import requests
import platform as pt
from environs import Env
from keyring.errors import NoKeyringError
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
            self.__db_object = SqliteDict(self._db, tablename=self._table_name, encode=json.dumps, decode=json.loads, autocommit=True)
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
        try:
            print(f"command {command}")
            # Run the command and capture its output
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)

            # Print the result
            print("Command output:")
            print(result)
        except subprocess.CalledProcessError as e:
            # If the command returns a non-zero exit status, handle the error
            print(f"Error: Command '{e.cmd}' returned non-zero exit status {e.returncode}")
            print("Error output:")
            print(e.output)
        
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
            ["awk", "{print $2,$3}", "OFS=^^"], stdin=command1_output.stdout)
    elif "alpine" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1}"], stdin=command1_output.stdout)
    elif "centos" in host_os:
        output = subprocess.check_output(
            ["awk", "{print $1,$2}", "OFS=^^"], stdin=command1_output.stdout)

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

def scan_snmp_ports(network_prefix, snmp_port):
    nm = nmap.PortScanner()
    scan_args = f"-p {snmp_port}"
    
    # Perform the SNMP port scan on the specified network range
    nm.scan(hosts=f"{network_prefix}/24", arguments=scan_args)
    
    # Iterate through the scan results and print hosts with the SNMP port open
    for host, scan_result in nm.all_hosts().items():
        if snmp_port in scan_result['tcp']:
            print(f"Host: {host} - SNMP Port {snmp_port} is open")
            

@click.command()
@click.option('--network-mode', is_flag=True, help='Run in network mode')
@click.option("-c", "--community", type=str, default="public",
              help="SNMP community used to authenticate the SNMP management station.", required=0)
@click.option("-d", "--device", type=IpType(), help="The device ip address.")
@click.argument("client-id", type=str, required=1)
@click.argument("secret-key", type=str, required=1)
@click.argument("envfile", type=str, required=0)
def cli(network_mode, client_id, secret_key, community, device, envfile):
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
                    with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "watchmanAgent.db", mode="write") as obj:
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
    if not network_mode:
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

    else:
        """
            By snmp mibs 
        """
        if community is None:
            custom_exit("Execution error: the snmp community is not specified.\n")
        else:
            hosts = get_network_hosts(device)
            report = getting_stacks_by_host_snmp(hosts, community)

            with open("_", "w+") as file:
                file.write("%s" % report)
            file.close()
            format_json_report(client_id, secret_key, "_")


if __name__ == "__main__":
    cli()
    
    network_prefix = "192.168.1"  # Change this to your network's prefix
    snmp_port = 161  # Default SNMP port
    
    scan_snmp_ports(network_prefix, snmp_port)
