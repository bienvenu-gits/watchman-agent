import configparser
import ipaddress
import json
import os
import threading

import platform as pt
import re
from typing import Union

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
from sqlitedict import SqliteDict
from pysnmp.entity.rfc3413.oneliner import cmdgen
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


class WatchmanCLI(click.Group):
    def resolve_command(self, ctx, args):
        if not args and not ctx.protected_args:
            args = ['default']
        return super(WatchmanCLI, self).resolve_command(ctx, args)


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


class IniFileConfiguration:
    _instance = None

    def __new__(cls, config_file_path=None):
        if not config_file_path:
            config_file_path = 'config.ini'

        if cls._instance is None:
            cls._instance = super(IniFileConfiguration, cls).__new__(cls)
            cls._instance.config = configparser.ConfigParser()
            cls._instance.config_file_path = config_file_path
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        if self.config_file_path is not None and os.path.exists(self.config_file_path):
            self.config.read(self.config_file_path)
        else:
            with open(self.config_file_path, 'w') as config_file:
                self.config.write(config_file)

    def get_value(self, section, key, default=None):
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def set_value(self, section, key, value):
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
        self.save_config_to_file()

    def ensure_update(self, old_config, new_config):
        return NotImplementedError

    def save_config_to_file(self):
        with open(self.config_file_path, 'w') as configfile:
            self.config.write(configfile)


class YamlFileConfiguration:
    _instance = None

    def __new__(cls, config_file_path=None):
        if not config_file_path:
            config_file_path = 'config.yml'

        if cls._instance is None:
            cls._instance = super(YamlFileConfiguration, cls).__new__(cls)
            cls._instance.config = {}
            cls._instance.config_file_path = config_file_path
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        if self.config_file_path is not None and os.path.exists(self.config_file_path):
            with open(self.config_file_path, 'r') as yaml_file:
                self.config = yaml.safe_load(yaml_file)
        else:
            # If it doesn't exist, create an empty YAML file
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump({}, yaml_file, default_flow_style=False)

    def get_value(self, *keys, default=None):
        try:
            config_section = self.config
            for key in keys:
                config_section = config_section.get(key, {})
            return config_section
        except (AttributeError, KeyError):
            return default

    def set_value(self, *keys, value):
        config_section = self.config
        for key in keys[:-1]:
            config_section = config_section.setdefault(key, {})
        config_section[keys[-1]] = value
        self.save_config_to_file()

    def ensure_update(self, old_config, new_config):
        if new_config:
            update_config_with_nested(old_config, new_config)

        try:
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump(old_config, yaml_file, default_flow_style=False)
            print(f"Configs successfully updated in '{yaml_file}'.")
        except yaml.YAMLError as e:
            print(f"Cannot update config file.")

    def save_config_to_file(self):
        if self.config and self.config_file_path:
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump(self.config, yaml_file, default_flow_style=False)


class Configuration:
    @staticmethod
    def create(config_file_path='config.yml'):
        if config_file_path and config_file_path.endswith('.yml'):
            return YamlFileConfiguration(config_file_path)
        else:
            return IniFileConfiguration(config_file_path)


def custom_exit(message: str):
    raise SystemExit(message)


"""
    Network Host Scanning
"""


def possible_hosts(cidr):
    # Extraire le nombre de bits hôtes du CIDR
    bits_hosts = 32 - int(cidr)

    # Calculer le nombre d'hôtes possibles (2^n - 2 où n est le nombre de bits hôtes)
    hosts = 2 ** bits_hosts - 2

    return hosts


def get_possible_active_hosts(ip_address, cidr):
    if not is_valid_ip(ip_address):
        raise ValueError("Invalid ip address")

    cidr_format = f'{ip_address}/{cidr}'
    # Utilisez la bibliothèque ipaddress pour analyser le CIDR
    network = ipaddress.IPv4Network(cidr_format, strict=False)

    # Obtenez la liste des adresses IP possibles dans le réseau
    hosts = set()

    threads = []
    for ip in network.hosts():
        if ip in (network.network_address, network.broadcast_address):
            # Skip network and broadcast addresses
            continue

        host = str(ip)
        thread = threading.Thread(target=scan_up_host_and_append, args=(host, hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


def get_network_ip_address(ip, cidr):
    if not is_valid_ip(ip):
        raise ValueError("Invalid ip address")

    cidr_format = f'{ip}/{cidr}'
    # Utilisez la bibliothèque ipaddress pour analyser le CIDR
    network = ipaddress.IPv4Network(cidr_format, strict=False)

    # Obtenez l'adresse réseau sous forme de chaîne de caractères
    ip_address = network.network_address

    return str(ip_address)


def is_valid_ip(ip):
    try:
        # Tentez de créer un objet IP à partir de la chaîne donnée
        ip = ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ip_active(ip, all_active=False):
    try:
        # Attempt to create a socket connection to the IP address and port 0
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            # Attempt to create a socket connection to the IP address and port 0 for IPv6
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def snmp_scanner(ip, ports: list = None):
    if ports is None:
        ports = [161]

    open_ports = []

    for port in ports:
        try:
            # Créez un objet socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Fixez un timeout court pour la connexion
            s.settimeout(1)

            # Tentez de se connecter à l'adresse IP et au port donnés
            s.connect((ip, port))
            # Si la connexion réussit, le port est ouvert
            print(f'IP : {ip}, Port: {port}, Status: open.')
            open_ports.append(port)
        except Exception as e:
            print(f'Connexion exception the host must probably filtering the port. Reason: {e}')
            print(f'IP : {ip}, Port: {port}, Status: closed.')
    return open_ports


def scan_snmp_and_append(ip, snmp_port, active_hosts):
    print(f"Scanning SNMP open host {ip}...")
    scan_result = snmp_scanner(ip=ip, ports=[snmp_port])
    if len(scan_result) > 0:
        active_hosts.add(ip)
    return active_hosts

def  reformating_version(version):
    patterns = [
        r'(\d+\.\d+\.\d+)',
        r'(\d+\.\d+\.\d+)[^\d]*(\d+)',
        r'(\d+\.\d+)[^\d]*(\d+)',
        r'(\d+(\.\d+)*)',
        r'(\b(\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?)\b)',
        r'(\b(\d+\.\d+\.\d+-\d+\.\w+)\b)',
        r'(\b(\d+)\b)',
        r'(\b(\d+(?:\.\d+)+)\b)',
        r'(\b([a-zA-Z]*\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?)\b)',
        r'(\b(\d{4}-\d{2}-\d{2})\b)',
        r'\b(\d+\.\d+\.\d+[-\w]*)\b',
        r'\b(\d+\.\d+\.\d+-\d+\.\w+)\b',
        r'\b[vV]?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?)\b',
        r'==(\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)?)$'                    
    ]
                # Define a regex pattern to match the version (digits and dots)
    for pattern in patterns:
                    # Use re.search to find the first match in the input string
        match = re.search(pattern, version)

                    # Check if a match was found
        if match:
            version = match.group(1)  # Extract the matched version
            break
        else:
            print("No version found in the input string.")
    return version


def snmp_query_v2(var_bind, hostname, community="public"):
    stacks = []
    # Create an SNMP command generator
    cmd_gen = cmdgen.CommandGenerator()

    # Perform the SNMP walk
    error_indication, error_status, error_index, var_bind_table = cmd_gen.nextCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((hostname, 161)),
        var_bind
    )

    # Check for errors
    if error_indication:
        print(f"SNMP Walk failed: {error_indication}")
    else:
        # print(f"var_bind_table {var_bind_table}")
        for var_bind_table_row in var_bind_table:
            # print(f"var_bind_table_row {var_bind_table_row}")
            for name, val in var_bind_table_row:
                name_version = val.prettyPrint()
                print(f"name_version {name_version}")
                item = name_version.split("_")
                version = reformating_version(item[1])
                item_version = {
                    "name": item[0],
                    "version": version
                }
                stacks.append(item_version)
    return stacks

def snmp_os_info_v2(var_bind, hostname, community="public"):
    # Create an SNMP command generator
    cmd_gen = cmdgen.CommandGenerator()

    # Perform the SNMP GET operation
    error_indication, error_status, error_index, var_binds = cmd_gen.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((hostname, 161)),
        var_bind
    )

    # Check for errors
    if error_indication:
        print(f"SNMP GET failed: {error_indication}")
        return None
    else:
        for name, val in var_binds:
            snmp_description = f"{name.prettyPrint()}: {val.prettyPrint()}"
            # Define regex patterns for hostname and OS name
            hostname_pattern = r'Linux\s+([^\s]+)'
            os_name_pattern = r'(\w+)\s+[\w.]+'

            # Use regex to extract the values
            hostname_match = re.search(hostname_pattern, snmp_description)
            os_name_match = re.search(os_name_pattern, snmp_description)

            # Check if matches were found and print the results
            if hostname_match:
                hostname = hostname_match.group(1)
                print("Hostname:", hostname)

            if os_name_match:
                os_name = os_name_match.group(1)
                print("OS Name:", os_name)
            return hostname, os_name
    return None


def snmp_query_v3(var_bind, hostname, username, auth_key, priv_key, auth_protocol=usmHMACSHAAuthProtocol,
                  priv_protocol=usmAesCfb128Protocol):
    snmp_engine = SnmpEngine()

    iterator = getCmd(
        snmp_engine,
        UsmUserData(username, auth_key, priv_key, auth_protocol, priv_protocol),
        UdpTransportTarget(hostname),
        ContextData(),
        var_bind
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
    else:
        return varBinds
    return None


def scan_up_host_and_append(ip, active_hosts):
    print(f"Scanning open host {ip}...")
    active = is_ip_active(ip=ip, all_active=True)
    if active:
        active_hosts.add(ip)
    return active_hosts


def get_snmp_hosts(network):
    print(f"Target network {network}")
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')
    active_hosts = set()
    cidr = config.get_value('network', 'cidr', default=24)
    snmp_port = config.get_value('network', 'snmp', 'port', default=161)

    if not network:
        raise ValueError("The network ip address must be provided.")

    if not snmp_port:
        raise ValueError("The configured snmp port must be provided.")

    hosts = get_possible_active_hosts(ip_address=network, cidr=cidr)

    threads = []
    for host in hosts:
        thread = threading.Thread(target=scan_snmp_and_append, args=(host, snmp_port, active_hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return active_hosts


"""
    Host Query by snmp
"""


def getting_stacks_by_host_snmp(active_hosts, community):
    hosts_report = {}
    os_hostname = None
    for host in active_hosts:
        var_bind = (1, 3, 6, 1, 2, 1, 25, 6, 3, 1, 2)
        snmp_query = snmp_query_v2(var_bind, host, community)
        oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)
        os_hostname, os_name = snmp_os_info_v2(oid, host, community)
        hosts_report[os_hostname] = {
            "os": os_name,
            "ipv4": host,
            "packages": snmp_query
        }
    return str(hosts_report)


"""
    Display an error message
"""


def request_error(error):
    click.echo(error)
    custom_exit(
        """
            Unable to join the server !
            Try one of the following solutions:
            \t\t- Try later
            \t\t- Verify your network connection
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
                    version=reformating_version(el[-1])
                    p_v = {
                        "name": " ".join(el[:-1]),
                        "version": version
                    }
                    if p_v["name"] != "":
                        packages_versions.append(p_v)

            except:
                pass
    elif host_os == "macOS":
        packages_versions = []
        status, output = subprocess.getstatusoutput(command)

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
                        package_name = package.split('.')[-1]
                        packages_versions.append(
                            {
                                "name": package_name,
                                "version":package_version
                            }
                        )
                    else:
                        packages_versions.append(
                            {
                                "name": package,
                                "version":None
                            }
                        )
                else:
                    print(f"Error retrieving package info for {package}: {package_info}")
        else:
            # An error occurred
            print(f"Error running 'pkgutil --pkgs': {output}")
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
            ["awk", "{print $2, $3}", "OFS=^^"], stdin=command1_output.stdout)
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
                    version = reformating_version(p_v[1])
                    name = p_v[0].split(":")
                    tab.append({
                        "name": name[0],
                        "version": version
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
                
                version = reformating_version(version)

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
        get_host_packages("pkgutil --pkgs",
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
        print(f"file_content {file_content}")
        response = requests.post(
            url=WEBHOOK_URL,
            headers={
                "AGENT-ID": client_id,
                "AGENT-SECRET": client_secret
            },
            data={
                "data": json.dumps(file_content)
            }
        )
        print(f"response {response}")
        print(f"response {response.status_code}")
        if response.status_code != 200:
            click.echo("\nExecution error️")
            click.echo("Message: ", response.json()["detail"])
    except requests.exceptions.RequestException as e:
        print(f"error on request {e}")
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
                command_output = subprocess.getstatusoutput(
                    f"snmpget -v3  -l authPriv -u {snmp_user} -a SHA -A {snmp_auth_key} -x AES -X {snmp_priv_key} {host} 1.3.6.1.2.1.25.6.3.1.2")
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

                command_output = subprocess.getstatusoutput(
                    f"snmpget -v3  -l authPriv -u {snmp_user} -a SHA -A {snmp_auth_key} -x AES -X {snmp_priv_key} {target_host} .1.3.6")
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


def read_config(config_file: str = None):
    if not config_file:
        file_name = 'config.yml'
    else:
        file_name = config_file

    try:
        with open(file_name, 'r') as config:
            loaded_config_data = yaml.safe_load(config)
        return loaded_config_data
    except FileNotFoundError:
        print(f"Config file '{file_name}' not found.")
        return None
    except Exception as e:
        print(f"Cannot read config file '{file_name}'")
        return None
    # if 'schedule' in loaded_config_data and 'hour_range' in loaded_config_data['schedule']:
    #     hour_range_value = loaded_config_data['schedule']['hour_range']


def update_config_with_nested(config, updated_config):
    if config:
        for key, value in updated_config.items():
            if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                # Recursively update nested dictionaries
                update_config_with_nested(config[key], value)
            elif key in config and isinstance(config[key], list) and isinstance(value, list):
                # Extend existing lists with new values
                config[key].extend(value)
            else:
                # Update or add a new key-value pair
                config[key] = value


def update_config(file_name, loaded_config_data, new_config):
    update_config_with_nested(loaded_config_data, new_config)
    try:
        with open(file_name, 'w') as fichier:
            yaml.dump(loaded_config_data, fichier, default_flow_style=False)
        print(f"Configs successfully written in '{file_name}'.")
    except yaml.YAMLError as e:
        print(f"Cannot write config file.")


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
        # target_host = get_public_ip(device)
        # hosts = get_snmp_hosts(device)
        hosts = ["209.97.189.19"]
        report = getting_stacks_by_host_snmp(hosts, community)

        with open("___", "w+") as file:
            file.write("%s" % report)
        file.close()
        format_json_report(client_id, secret_key, "___")


def scan_network(ip, mask, port):
    network = ip.split('.')[:3]  # Get the first three octets of the IP address
    for i in range(1, 256):
        target_ip = f"{network[0]}.{network[1]}.{network[2]}.{i}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Set a timeout for the connection attempt
                s.connect((target_ip, port))
                print(f"Port {port} is open on {target_ip}")
        except (socket.timeout, ConnectionRefusedError):
            pass


@click.command(cls=WatchmanCLI)
def cli():
    pass


@cli.group(name="configure", help='Save configuration variables to the config file')
def configure():
    pass


@configure.command(name="connect", help='Save connect configuration variables')
@click.option("-m", "--mode", type=str, default='network',
              help="Runtime mode for agent execution [network/agent]. Default: agent", required=False)
@click.option("-c", "--client-id", type=str, help="Client ID for authentication purpose", required=True)
@click.option("-s", "--client-secret", type=str, help="Client Secret for authentication purpose", required=True)
def configure_connect(mode, client_id, client_secret):
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')
    section = 'runtime'

    if mode:
        config.set_value(section, 'mode', value=mode)

    if client_id:
        config.set_value(section, 'client_id', value=client_id)

    if client_secret:
        config.set_value(section, 'secret_key', value=client_secret)


@configure.command(name="network", help='Save network configuration variables')
@click.option("-t", "--network-target", type=IpType(), help="The network target ip address.", required=False)
@click.option("-m", "--cidr", type=int, help="The mask in CIDR annotation. Default: 24 \neg: --cidr 24", default=24,
              required=True)
@click.option("-c", "--snmp-community", type=str, help="SNMP community used to authenticate the SNMP management "
                                                       "station.\nDefault: 'public'", required=1, default='public')
@click.option("-p", "--snmp-port", type=int, help="SNMP port on which clients listen to. \n Default: 161",
              required=True, default=161)
@click.option("-u", "--snmp-user", type=str, help="SNMP authentication user ", required=False)
@click.option("-a", "--snmp-auth-key", type=str, help="SNMP authentication key", required=False)
@click.option("-s", "--snmp-priv-key", type=str, help="SNMP private key", required=False)
@click.option("-e", "--exempt", type=str, help="Device list to ignore when getting stacks. eg: --exempt "
                                               "192.168.1.12,", required=False)
def configure_network(snmp_community, snmp_port, network_target, cidr, exempt, snmp_auth_key, snmp_priv_key, snmp_user):
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')
    section = 'network'
    if snmp_community:
        config.set_value(section, 'snmp', 'v2', 'community', value=snmp_community)

    if snmp_user:
        config.set_value(section, 'snmp', 'v3', 'user', value=snmp_user)

    if snmp_auth_key:
        config.set_value(section, 'snmp', 'v3', 'auth_key', value=snmp_auth_key)

    if snmp_priv_key:
        config.set_value(section, 'snmp', 'v3', 'priv_key', value=snmp_priv_key)

    if exempt:
        exempt = [w for w in str(exempt).strip().split(',') if w != ""]
        cfg_exempt = config.get_value(section, 'exempt', default=[])
        if cfg_exempt:
            cfg_exempt.extend(exempt)
        else:
            cfg_exempt = exempt

        config.set_value(section, 'exempt', value=list(set(cfg_exempt)))

    if snmp_port:
        config.set_value(section, 'snmp', 'port', value=snmp_port)
        # config.set_value(section, 'snmp', 'v2', 'port', value=snmp_port)
        # config.set_value(section, 'snmp', 'v3', 'port', value=snmp_port)

    if network_target:
        config.set_value(section, 'ip', value=network_target)

    if cidr:
        config.set_value(section, 'cidr', value=cidr)


@configure.command(name="schedule", help='Save schedule configuration variables')
@click.option("-m", "--minute", type=int, help="Execution every minute. Default: 15", required=True)
@click.option("-h", "--hour", type=int, help="Execution every hour.", required=False)
@click.option("-d", "--day", type=int, help="Execution every day.", required=False)
@click.option("-mo", "--month", type=int, help="Execution every month.", required=False)
def configure_schedule(minute, hour, day, month):
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')
    section = 'schedule'

    if minute:
        config.set_value(section, 'minute', value=minute)
    else:
        config.set_value(section, 'minute', value=15)

    if hour:
        config.set_value(section, 'hour', value=hour)
    else:
        config.set_value(section, 'hour', value='*')

    if day:
        config.set_value(section, 'day', value=day)
    else:
        config.set_value(section, 'day', value='*')

    if month:
        config.set_value(section, 'month', value=month)
    else:
        config.set_value(section, 'month', value='*')


@cli.command(name='run', help='Attach monitoring to cron job and watch for stacks')
def run():
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')

    mode = config.get_value('runtime', 'mode', default='network')
    client_id = config.get_value('runtime', 'client_id')
    secret_key = config.get_value('runtime', 'secret_key')

    community = config.get_value('network', 'snmp', 'v2', 'community', default='public')
    network = config.get_value('network', 'ip')

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
        run_network(community=community, device=network, client_id=client_id, secret_key=secret_key)
        # schedule.every(hour_range).hours.do(run_network, community=community, device=ip, client_id=client_id, secret_key=secret_key)

    # while True:
    #     schedule.run_pending()
    #     time.sleep(10)


if __name__ == "__main__":
    # if len(sys.argv) == 1:
    #     sys.argv.append('run')
    cli()
