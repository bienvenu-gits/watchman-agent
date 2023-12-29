import asyncio
import binascii
import configparser
import ipaddress
import json
import logging
import os
import threading
import csv
import platform as pt
import time
import subprocess
from pprint import pprint

import platformdirs
import yaml
import getmac
import platform
import socket
from pathlib import Path
import click
import keyring
import requests
from environs import Env
from keyring.errors import NoKeyringError
from pysnmp.hlapi import *
from sqlitedict import SqliteDict
from semver.version import Version as sem_version
from packaging import version as pkg_version
# import pandas as pd
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

"""
    Set config directory and files
"""
data_dir = platformdirs.user_config_dir('WatchmanAgent')
os.makedirs(data_dir, exist_ok=True)
config_file = "config.yml"
tracking_file = "track.yml"
result_file = "data.json"
config_file = os.path.join(data_dir, config_file)
tracking_file = os.path.join(data_dir, tracking_file)
result_file = os.path.join(data_dir, result_file)

"""
    Fetch Variables environment
"""
env = Env()
env.read_env()
ENV = env("ENV_MODE", default="production")

WEBHOOK_URL = env("WEBHOOK_URL", default="https://watchman.bj/api/agents/webhook/")
CONNECT_URL = env("CONNECT_URL", default='https://watchman.bj/api/agents/connect')

if ENV == "development":
    # Override production env variable in development
    WEBHOOK_URL = env("DEV_WEBHOOK_URL", default="http://localhost:3000/api/agents/webhook/")
    CONNECT_URL = env("DEV_CONNECT_URL", default="http://localhost:3000/api/agents/connect")

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
            ipaddress.ip_network(value)
        except:
            try:
                ipaddress.ip_address(value)
            except ValueError as e:
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
            config_file_path = config_file

        if cls._instance is None:
            cls._instance = super(YamlFileConfiguration, cls).__new__(cls)
            cls._instance.config = {}
            cls._instance.config_file_path = config_file_path
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        if self.config_file_path is not None and os.path.exists(self.config_file_path):
            # click.echo(f"Loading config from {self.config_file_path}")
            click.echo(f"[+] - Loading agent configuration...")
            with open(self.config_file_path, 'r') as yaml_file:
                self.config = yaml.safe_load(yaml_file)
        else:
            # click.echo(f"Loading config from {self.config_file_path}")
            click.echo(f"[+] - Loading agent configuration...")
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
            print(f"Cannot update config file. {e}")

    def read_and_display_config(self):
        click.echo(f"[+] - Displaying agent configuration...")
        config = {}
        for key, value in self.config.items():
            self._display_config_recursive(key, value, config)
        pprint(config, indent=2, sort_dicts=True)

    def _display_config_recursive(self, prefix, config_section, config):
        if isinstance(config_section, dict):
            config[prefix] = config_section
        else:
            config[prefix] = config_section

    def save_config_to_file(self):
        if self.config and self.config_file_path:
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump(self.config, yaml_file, default_flow_style=False)


class Tracking:
    def __init__(self, file_path, backup_path):
        self.file_path = file_path
        self.backup_path = backup_path
        self.current_data = None
        self.previous_data = None

    def read_file(self):
        with open(self.file_path, 'r') as file:
            self.current_data = json.load(file)

    def save_backup(self):
        if not os.path.exists(self.backup_path):
            os.makedirs(self.backup_path)

        backup_file = os.path.join(self.backup_path, f"backup_{len(os.listdir(self.backup_path)) + 1}.json")

        if self.current_data is not None:
            with open(backup_file, 'w') as file:
                json.dump(self.current_data, file, indent=2)

    def track_changes(self):
        if self.previous_data is None:
            print("No previous data to compare.")
            return

        changes = {
            "added": {},
            "modified": {},
            "deleted": {}
        }

        for key in set(self.current_data.keys()).union(set(self.previous_data.keys())):
            if key not in self.previous_data:
                changes["added"][key] = self.current_data[key]
            elif key not in self.current_data:
                changes["deleted"][key] = self.previous_data[key]
            elif self.current_data[key] != self.previous_data[key]:
                changes["modified"][key] = {
                    "old_value": self.previous_data[key],
                    "new_value": self.current_data[key]
                }

        return changes

    def isolate_changes(self, changes_file_path):
        changes = self.track_changes()
        if not changes:
            print("No changes detected.")
            return

        with open(changes_file_path, 'w') as file:
            json.dump(changes, file, indent=2)

    def display_changes(self):
        changes = self.track_changes()

        if not changes:
            print("No changes to display.")
            return

        print("Changes:")
        print(json.dumps(changes, indent=2))

    def update_file(self, new_data):
        self.read_file()
        self.previous_data = deepcopy(self.current_data)
        self.current_data = new_data

        with open(self.file_path, 'w') as file:
            json.dump(new_data, file, indent=2)


class Configuration:
    @staticmethod
    def load(config_file_path=config_file):
        if config_file_path and config_file_path.endswith('.yml'):
            return YamlFileConfiguration(config_file_path)
        else:
            return IniFileConfiguration(config_file_path)


def custom_exit(message: str):
    raise SystemExit(message)


def get_possible_active_hosts(ip_address, cidr, exempt):
    if not is_valid_ip(ip_address):
        raise ValueError(f"Invalid ip address {ip_address}")

    cidr_format = f'{ip_address}/{cidr}'
    # Utilisez la bibliothèque ipaddress pour analyser le CIDR
    network = ipaddress.IPv4Network(cidr_format, strict=False)

    # Obtenez la liste des adresses IP possibles dans le réseau
    hosts = set()

    threads = []
    exempt.append(str(network.network_address))
    exempt.append(str(network.broadcast_address))
    for ip in network.hosts():
        host = str(ip)
        if host in exempt:
            # Skip exempted address
            continue

        thread = threading.Thread(target=scan_up_host_and_append, args=(host, hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


def get_possible_active_hosts_by_range(ip_start, ip_end, exempt):
    def generate_ip_range(start_ip, end_ip):
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        ips = list(ipaddress.summarize_address_range(start, end))
        ip_list = []
        for network in ips:
            ip_list.extend(list(network.hosts()))
        # Include the start IP in the list
        ip_list.append(start)
        return ip_list

    if not is_valid_ip(ip_start):
        raise ValueError(f"Invalid range start ip address {ip_start}")

    if not is_valid_ip(ip_end):
        raise ValueError(f"Invalid range end ip address {ip_end}")

    ip_range = generate_ip_range(ip_start, ip_end)

    # Obtenez la liste des adresses IP possibles dans le réseau
    hosts = set()

    threads = []
    for ip in ip_range:
        host = str(ip)
        if host in exempt:
            # Skip exempted addresses
            continue
        thread = threading.Thread(target=scan_up_host_and_append, args=(host, hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


def is_valid_ip(ip):
    try:
        # Tentez de créer un objet IP à partir de la chaîne donnée
        ip = ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ip_active(ip, all_active=False):
    if all_active:
        return True

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


linux_version_pattern = re.compile(
    r"^"
    # epoch must start with a digit
    r"(\d+:)?"
    # upstream must start with a digit
    r"\d"
    r"("
    # upstream  can contain only alphanumerics and the characters . + -
    # ~ (full stop, plus, hyphen, tilde)
    r"[A-Za-z0-9\.\+\~\-]+"
    r"|"
    # If there is no debian_revision then hyphens are not allowed in version.
    r"[A-Za-z0-9\.\+\~]+-[A-Za-z0-9\+\.\~]+"
    r")?"
    r"$"
)
irregular_version_pattern = re.compile(r'\d+(\.\d+)*')


def parse_version(text):
    """ Semantic Versioning (SemVer)
     Date-based Versioning
     Alphanumeric or Custom Schemes
     Debian based version parser
     Ubuntu based version parser
     parse version with build:
    """
    if not text:
        return None

    if linux_version_pattern.match(text):
        match = linux_version_pattern.search(text)
        if match:
            version = match.group()
            if ":" in version:
                epoch, _, version = version.partition(":")
                epoch = int(epoch)
            else:
                epoch = 0

            if "-" in version:
                upstream, _, revision = version.rpartition("-")
            else:
                upstream = version
                revision = "0"

            version = upstream
            regex_matched = False

            if 'ubuntu' in version:
                match = irregular_version_pattern.search(version)
                if match:
                    regex_matched = True
                    version = match.group()
            elif 'debian' in version:
                match = irregular_version_pattern.search(version)
                if match:
                    regex_matched = True
                    version = match.group()
            elif 'git' in version:
                match = irregular_version_pattern.search(version)
                if match:
                    regex_matched = True
                    version = match.group()
            elif '-' in version:
                match = irregular_version_pattern.search(version)
                if match:
                    regex_matched = True
                    version = match.group()
            else:
                match = irregular_version_pattern.search(version)
                if match:
                    regex_matched = True
                    version = match.group()

            parsed = None
            if not regex_matched:
                try:
                    parsed = sem_version.parse(version)
                except ValueError:
                    try:
                        parsed = pkg_version.parse(version)
                    except pkg_version.InvalidVersion:
                        parsed = None

            if parsed:
                parsed_split_len = len(str(parsed).split("."))
                if parsed_split_len < 3:
                    version = [str(parsed.major), str(parsed.minor)]
                elif parsed_split_len == 3:
                    try:
                        version = [str(parsed.major), str(parsed.minor), str(parsed.patch)]
                    except AttributeError:
                        version = [str(parsed.major), str(parsed.minor), str(parsed.micro)]
                else:
                    version = parsed

                if isinstance(version, list):
                    version = ".".join(version)
                else:
                    version = version
            else:
                if not regex_matched:
                    print(f'Cannot definitely parse version {text}')
            return version


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
            open_ports.append(port)
        except Exception as e:
            print(f'Connexion exception the host must probably filtering the port. Reason: {e}')
    return open_ports


def scan_snmp_and_append(ip, snmp_port, active_hosts):
    scan_result = snmp_scanner(ip=ip, ports=[snmp_port])
    if len(scan_result) > 0:
        active_hosts.add(ip)
    return active_hosts


def reformatting_version(version):
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
        re.search(pattern, version)


def coroutine_wrapper(coroutine):
    asyncio.run(coroutine)


def get_mac_address():
    try:
        mac_address = getmac.get_mac_address()
        return mac_address
    except Exception as e:
        click.echo(f'Cannot find host mac address: {e}')
        return None


def get_os_architecture():
    try:
        architecture, _ = platform.architecture()
        return architecture
    except Exception as e:
        return f"Error: {e}"


def get_ip_address():
    try:
        # Create a socket object to get the local machine's IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google's public DNS server
        ip_address = s.getsockname()[0]  # Get the local IP address
        s.close()
        return ip_address
    except Exception as e:
        click.echo(f'Cannot find host ip address: {e}')
        return None


def extract_info_linux(package_string):
    # Original regular expression pattern
    original_pattern = r'^(.*?)_([^_]+)_([^\s]+)$'

    # Additional pattern to handle strings like "whiptail-0.52.20-1ubuntu1"
    additional_pattern = r'^([^-\s]+)-([\d.]+)-(\S+)$'

    # Pattern for strings like "ncurses-6.1-10.20180224.el8"
    new_pattern = r'^([^-\s]+)-([\d.]+)-([\d.]+)\.([^\s]+)$'

    # Pattern for strings like "ncurses-6.1-10.20180224.el8"
    second_pattern = r'(.*)-(.*)-(.*).(.*)'
    third_pattern = r'\d+(\.\d+)*'

    # Try the original pattern first
    match = re.match(original_pattern, package_string)

    if match:
        name = match.group(1)
        version = match.group(2)
        architecture = match.group(3)
        return {"name": name, "version": version, "arch": architecture}
    else:
        # If the original pattern didn't match, try the additional pattern
        match = re.match(additional_pattern, package_string)

        if match:
            name = match.group(1)
            version = match.group(2)
            architecture = match.group(3)
            return {"name": name, "version": version, "arch": architecture}
        else:
            # If the additional pattern didn't match, try the new pattern
            match = re.match(new_pattern, package_string)

            if match:
                name = match.group(1)
                version = match.group(2)
                release = match.group(3)
                architecture = match.group(4)
                return {"name": name, "version": version, "arch": architecture}
            else:
                # If the new pattern didn't match, try the second pattern
                match = re.match(second_pattern, package_string)

                if match:
                    name = match.group(1)
                    version = match.group(2)
                    release = match.group(3)
                    architecture = match.group(4)
                    return {"name": name, "version": version, "arch": architecture}
                else:
                    return None


def extract_info_windows(package_string):
    try:
        # Essayer de décoder la chaîne hexadécimale
        decoded_string = binascii.unhexlify(package_string[2:]).decode('latin-1')

        # Utilisation d'une expression régulière pour extraire le nom, la version et l'architecture sous Windows
        pattern = r'^(.*?)\s*-\s*(.*?)\s*\((.*?)\)$'
        match = re.match(pattern, decoded_string)

        if match:
            name = match.group(1)
            version = match.group(2)
            architecture = match.group(3)
            return {"name": name, "version": version, "architecture": architecture}
        else:
            return {"name": decoded_string, "version": None, "architecture": None}
    except (binascii.Error, ValueError):
        # La chaîne n'est pas hexadécimale, traiter comme une chaîne normale
        pattern = r'^(.*?)\s*-\s*(.*?)\s*\((.*?)\)$'
        match = re.match(pattern, package_string)

        if match:
            name = match.group(1)
            version = match.group(2)
            architecture = match.group(3)
            return {"name": name, "version": version, "architecture": architecture}
        else:
            return {"name": package_string, "version": None, "architecture": None}


def extract_windows_host_info(input_str):
    # Expression régulière pour extraire l'architecture matérielle (premier mot après "Hardware:")
    hardware_architecture_pattern = r'Hardware:\s(\S+)'

    # Expression régulière pour extraire les informations logicielles
    software_pattern = r'Software:\s(.*?)\sVersion\s(\d+\.\d+).*\(Build\s(\d+)\s.*\)$'

    # Rechercher les correspondances dans la chaîne d'entrée
    hardware_architecture_match = re.search(hardware_architecture_pattern, input_str, re.IGNORECASE)
    software_match = re.search(software_pattern, input_str)

    # Extraire l'architecture matérielle
    hardware_architecture = hardware_architecture_match.group(1).strip() if hardware_architecture_match else None

    # Extraire les informations logicielles
    software_name = software_match.group(1).strip() if software_match else None
    software_version = software_match.group(2).strip() if software_match else None
    software_build = software_match.group(3).strip() if software_match else None

    return {
        "arch": hardware_architecture,
        "os_name": software_name,
        "kernel_version": software_version,
        "build": software_build
    }


def extract_info_macos(package_string):
    # Utilisation d'une expression régulière pour extraire le nom et la version sous macOS
    pattern = r'^(.*?)\s+(\S+)\s*$'
    match = re.match(pattern, package_string)

    if match:
        name = match.group(1)
        version = match.group(2)
        if '(null)' in version:
            version = None
        if '(null)' in name:
            name = None
        return {"name": name, "version": version, "arch": None}
    else:
        return None


async def get_packages_async(hostname, community, os_name):
    var_bind = '1.3.6.1.2.1.25.6.3.1.2'

    def parse_version_append(ver, res, host):
        ver = parse_version(ver)
        d = {
            "name": pkg_info['name'].replace('"', ",") if '"' in pkg_info['name'] else pkg_info['name'],
            "version": ver,
        }
        res.append(d)

    iterator = await snmp_query_v2(var_bind=var_bind, hostname=hostname, community=community)
    result = []
    parsed_values = await parse_snmp_response(iterator, var_bind)
    threads = []
    extract_fnc = extract_info_windows
    if os_name == "linux":
        extract_fnc = extract_info_linux
    else:
        extract_fnc = extract_info_macos

    for value in parsed_values:
        pretty_value = value.prettyPrint()
        pkg_info = extract_fnc(pretty_value)
        if pkg_info:
            thread = threading.Thread(target=parse_version_append,
                                      args=(pkg_info['version'], result, hostname))
            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()
    return result


async def get_host_info_async(hostname, community):
    var_binds = {
        'sys_hostname_bind': '1.3.6.1.2.1.1.5.0',
        'sys_descr_bind': '1.3.6.1.2.1.1.1.0',
    }
    result = {}
    for var_bind_name, var_bind_value in var_binds.items():
        iterator = await snmp_get_query_v2(var_bind=var_bind_value, hostname=hostname, community=community)
        parsed_values = await parse_snmp_response(iterator, var_bind_value)
        for value in parsed_values:
            value = value.prettyPrint()
            lower_value = value.lower()
            if var_bind_name == 'sys_hostname_bind':
                result["host_name"] = value
                result["mac"] = getmac.get_mac_address(ip=hostname)
            elif var_bind_name == 'sys_descr_bind':
                if "windows" in lower_value:
                    info = extract_windows_host_info(value)
                    result["os_name"] = info.get("os_name")
                    result["kernel_version"] = info.get("kernel_version")
                    result["arch"] = info.get("arch")
                    result["build"] = info.get("build")
                elif "darwin" in lower_value:
                    partitioned = value.split()
                    if partitioned:
                        result["os_name"] = partitioned[0]
                        result["kernel_version"] = partitioned[2]
                        result["arch"] = partitioned[-1]
                elif "linux" in lower_value:
                    partitioned = value.split()
                    if partitioned:
                        result["os_name"] = partitioned[0]
                        result["kernel_version"] = partitioned[2]
                        result["arch"] = partitioned[-1]
                else:
                    print("Cannot parse unix based host informations.")
    return result


async def parse_snmp_response(iterator, var_bind):
    def sub_thread_iter(bind, var, res, stop):
        oid, value = bind
        if var not in str(oid):
            stop.set()  # Utilisez .set() pour définir la variable de contrôle à True
        else:
            res.append(value)

    def threaded_iterator(indication, status, binds, stop, res, var_b):
        if indication:
            return
        elif status:
            return
        else:
            sub_threads = []
            for bind in binds:
                th = threading.Thread(target=sub_thread_iter, args=(bind, var_b, res, stop))
                th.start()
                if stop.is_set():  # Utilisez .is_set() pour vérifier la variable de contrôle
                    break
                sub_threads.append(th)

            for th in sub_threads:
                th.join()

    result = []
    stop_loop = threading.Event()  # Utilisez un objet Event pour la variable de contrôle
    threads = []
    for error_indication, error_status, error_index, var_binds in iterator:
        thread = threading.Thread(target=threaded_iterator,
                                  args=(error_indication, error_status, var_binds, stop_loop, result, var_bind))
        thread.start()
        if stop_loop.is_set():  # Utilisez .is_set() pour vérifier la variable de contrôle
            break
        threads.append(thread)

    for thread in threads:
        thread.join()
    return result


async def snmp_query_v2(var_bind, hostname, community="public"):
    snmp_engine = SnmpEngine()
    return nextCmd(
        snmp_engine,
        CommunityData(community),
        UdpTransportTarget((hostname, 161), timeout=2.0, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(var_bind)),
    )


async def snmp_get_query_v2(var_bind, hostname, community="public"):
    snmp_engine = SnmpEngine()
    try:
        return getCmd(
            snmp_engine,
            CommunityData(community),
            UdpTransportTarget((hostname, 161), timeout=2.0, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(var_bind)),
        )
    except:
        return None


async def snmp_query_v3(var_bind, hostname, username, auth_key, priv_key, auth_protocol=usmHMACSHAAuthProtocol,
                        priv_protocol=usmAesCfb128Protocol):
    snmp_engine = SnmpEngine()
    try:
        return nextCmd(
            snmp_engine,
            UsmUserData(username, auth_key, priv_key, auth_protocol, priv_protocol),
            UdpTransportTarget(hostname),
            ContextData(),
            ObjectType(ObjectIdentity(var_bind)),
        )
    except:
        return None


def scan_up_host_and_append(ip, active_hosts):
    active = is_ip_active(ip=ip, all_active=True)
    if active:
        active_hosts.add(ip)
    return active_hosts


def get_snmp_hosts(network, use_range, range_start, range_end):
    config = Configuration.load(config_file_path=config_file)
    active_hosts = set()
    cidr = config.get_value('network', 'cidr', default=24)
    exempt = config.get_value('network', 'exempt')
    snmp_port = config.get_value('network', 'snmp', 'port', default=161)

    if not snmp_port:
        raise ValueError("The configured snmp port must be provided.")

    if network and use_range:
        if not range_start or not range_end:
            raise ValueError("The network range ip address must be provided.")
        hosts = get_possible_active_hosts_by_range(range_start, range_end, exempt=exempt)
    else:
        hosts = get_possible_active_hosts(ip_address=network, cidr=cidr, exempt=exempt)

    threads = []
    for host in hosts:
        thread = threading.Thread(target=scan_snmp_and_append, args=(host, snmp_port, active_hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
    return active_hosts


async def handle_multi_async_operation(host, community, hosts_report):
    try:
        start = time.perf_counter()
        os_info = await get_host_info_async(host, community)
        end = time.perf_counter()
        if os_info:
            click.echo(f'Getting packages for Host: {host}')
            start = time.perf_counter()
            packages = await get_packages_async(host, community, os_name=os_info.get('os_name').lower())
            end = time.perf_counter()
            hosts_report[host] = {
                "os": os_info,
                "ipv4": host,
                "packages": packages
            }
    except:
        pass


async def getting_stacks_by_host_snmp(active_hosts, community):
    hosts_report = {}
    for host in active_hosts:
        try:
            click.echo(f'[+] - Getting assets for Host: {host}')
            os_info = await get_host_info_async(host, community)
            if os_info:
                packages = await get_packages_async(host, community, os_name=os_info.get('os_name').lower())
                hosts_report[host] = {
                    "os": os_info,
                    "ipv4": host,
                    "packages": packages
                }
        except Exception as e:
            click.echo(f'Unexpected error occurred: {e}')
    return json.dumps(hosts_report)


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


def parse_dpkg():
    output = subprocess.check_output(["dpkg", "-l"]).decode("utf-8")
    lines = output.strip().split("\n")

    # Skip the first 5 lines which contain the header information
    data_lines = lines[5:]

    packages = []
    for line in data_lines:
        split_line = line.split(None, 3)
        # Each line has 4 columns: status, name, version, architecture
        status, name, version, architecture = split_line
        reformatting_version(version)
        version = parse_version(version)
        name = name.split(":")[0]
        package = {"name": name, "version": version}
        packages.append(package)

    return packages


"""
    Get packages and version result from command line
"""


def get_host_packages(command, host_os, file, container):
    """
        Get installed stacks on the host machine locally

    Parameters
    ----------
    command
    host_os
    file
    container

    Returns
    -------
    None
    """

    mac = get_mac_address()
    ip = get_ip_address()
    architecture = get_os_architecture()

    if ip:
        hostname = get_os_hostname(ip)
    else:
        hostname = None

    if host_os == 'windows':
        command_output = subprocess.check_output(command, text=True)
        output_list = command_output.split('\n')
        packages_versions = []
        for el in output_list:
            el = el.split()
            el = [i for i in el if i != '']  # purge space
            try:
                if el[-1][0].isdigit() and el[-1][-1].isdigit():
                    reformatting_version(el[-1])
                    version = parse_version(el[-1])
                    p_v = {
                        "name": " ".join(el[:-1]),
                        "version": version
                    }
                    if p_v["name"] != "":
                        packages_versions.append(p_v)
            except:
                pass
    elif host_os == "darwin":
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
                                "version": package_version
                            }
                        )
                    else:
                        packages_versions.append(
                            {
                                "name": package,
                                "version": None,
                            }
                        )
                else:
                    print(f"Error retrieving package info for {package}: {package_info}")
        else:
            # An error occurred
            print(f"Error running 'pkgutil --pkgs': {output}")
    elif 'kali' in host_os:
        packages_versions = parse_dpkg()
    else:
        command_output = subprocess.Popen(command, stdout=subprocess.PIPE)
        packages_versions = format_pkg_version(command_output, host_os)

    os_info = {
        "os_name": host_os,
        "mac": mac,
        "arch": architecture,
        "host_name": hostname,
        "kernel_version": platform.release()
    }

    if container is None:
        file.writelines([
            "\"os\" : %s , " % os_info,
            "\"packages\" : %s ," % packages_versions,
            "\"mac\" : \"%s\" , " % mac,
            "\"architecture\": \"%s\"," % architecture,
            "\"ipv4\": \"%s\"," % ip,
            "\"containers\" : [ "
        ])
        click.echo("\n + Successfully retrieve installed stacks for %s !!!\n" % host_os)
    else:

        file.writelines([

            " { "
            " \"name\" : \"%s\" ," % container,
            " \"packages\" : %s " % packages_versions,
            " } "

        ])

        click.echo(
            f" + Successfully retrieved installed stacks for container {container} in {host_os} successfully !!!\n")


def get_host_os():
    """
        Function to find the host operating system
    Returns
    host operating system name
    -------

    """
    platform_system = pt.system()
    check_hostname_ctl = False
    if platform_system == 'Windows':
        return 'windows'
    elif platform_system == 'Linux':
        check_hostname_ctl = True
    elif platform_system == 'Darwin':
        command_output = subprocess.run(["sw_vers"], stdout=subprocess.PIPE)
        command_output_lines = command_output.stdout.decode("utf-8").split('\n')
        mac = re.search("macOS", str(command_output_lines))
        if mac:
            return "macos"
        else:
            print("Cannot find host operating system.")
            return platform_system.lower()

    if check_hostname_ctl:
        command_output = subprocess.run(["hostnamectl"], stdout=subprocess.PIPE)
        command_output_lines = command_output.stdout.decode("utf-8").split('\n')

        for line in command_output_lines:
            if "system" in line.lower():
                return line.split(':')[-1].lower().lstrip()


def get_os_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return None


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
                    reformatting_version(p_v[1])
                    version = parse_version(p_v[1])
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
                reformatting_version(version)
                version = parse_version(version)
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


def get_host_info_and_installed(file):
    host_os = get_host_os()
    if host_os == 'windows':
        get_host_packages(
            ["powershell", "-Command", "Get-Package", "|", "Select", "Name,Version"], host_os, file, None)
    elif host_os in ["darwin", "macos"]:
        get_host_packages("pkgutil --pkgs",
                          host_os, file, None)
    else:
        if "alpine" in host_os:
            get_host_packages(["apk", "info", "-vv"], host_os, file, None)
        elif "ubuntu" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "debian" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "kali" in host_os:
            get_host_packages(["dpkg", "-l"], host_os, file, None)
        elif "rehl" in host_os:
            get_host_packages(["rpm", "-qa"], host_os, file, None)
        elif "centos" in host_os:
            get_host_packages(["yum", "list", "installed"],
                              host_os, file, None)
        else:
            custom_exit(f"The actual Operating System {host_os} is not supported yet.\n")

    # start container inspection
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
    try:
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
        if response.status_code != 200:
            click.echo("\nError! Unable to send assets..")
            custom_exit(f"Reason: {response.json()['detail']}")
        else:
            click.echo('\n[+] - Successfully sent assets...')

        with open(file, "w+") as file_in_write_mode:
            file_in_write_mode.write("")
    except requests.exceptions.RequestException as e:
        request_error(error=e)


def export_data_to_csv(file, export_path):
    file_content = ""
    with open(file, "r+") as file_in_read_mode:
        file_content = file_in_read_mode.read()
    file_content = re.sub('\'', '"', file_content)
    data = file_content

    # Parse JSON
    data = json.loads(data)
    csv_file = export_path
    # Open CSV file for writing
    with open(csv_file, 'w', newline='') as csvfile:
        # Create CSV writer object
        csv_writer = csv.writer(csvfile)

        # Write header
        csv_writer.writerow(
            ["ip", "mac", "architecture", "hostname", "os", "stack_name", "stack_version", "stack_type",
             "host_machine",
             "host_machine_architecture", "host_machine_os", "host_machine_hostname", "host_machine_mac"])
        for key in data:
            # Write data
            for package in data[key]["packages"]:
                csv_writer.writerow(
                    [data[key]["ipv4"], data[key]["mac"], data[key]["architecture"], key,
                     data[key]["os"]['os_name'], package["name"], package["version"]])
    return csv_file


def export_network_data_to_csv(file, export_path):
    file_content = ""
    with open(file, "r+") as file_in_read_mode:
        file_content = file_in_read_mode.read()
    file_content = re.sub('\'', '"', file_content)
    data = file_content

    # Parse JSON
    data = json.loads(data)
    csv_file = export_path
    # Open CSV file for writing
    with open(csv_file, 'w', newline='') as csvfile:
        # Create CSV writer object
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(
            ["ip", "mac", "architecture", "hostname", "os", "stack_name", "stack_version", "stack_type",
             "host_machine",
             "host_machine_architecture", "host_machine_os", "host_machine_hostname", "host_machine_mac"])

        for key in data:
            # Write data
            for package in data[key]["packages"]:
                csv_writer.writerow(
                    [data[key]["ipv4"], data[key]['os'].get('mac', None), data[key]['os']["arch"],
                     data[key]['os']['host_name'],
                     data[key]["os"]['os_name'], package["name"], package["version"]])
    return csv_file


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
        print(f"Cannot write config file. {e}")


def run_mode_agent(client_id, secret_key, export, export_path, export_file):
    """
        Function to handle agent mode execution

    Parameters
    ----------
    client_id
    secret_key
    export: define if data must be exported
    export_path
    export_file

    Returns
    -------
    None
    """

    if export is True:
        click.echo('Exportation activated. Assets will not sent online...')

    with open("data", "w+") as file:
        # write the opening bracket of the json object
        file.writelines(["{"])

        file.writelines(["  \"%s\" : { " % pt.node(), ])

        get_host_info_and_installed(file)

        file.writelines([" ] } } "])

    file.close()
    if export is True:
        full_path = Path(export_path) / export_file
        export_data_to_csv("data", full_path)
        custom_exit(f'Successfully exported assets to file {full_path}')
    else:
        format_json_report(client_id, secret_key, "data")


def run_mode_network(
        community: str,
        device: str,
        use_range: bool,
        range_start: str,
        range_end: str,
        client_id: str,
        secret_key: str,
        export: bool,
        export_path: str,
        export_file: str
) -> None:
    """

    Parameters
    ----------
    community
    device
    use_range
    range_start
    range_end
    client_id
    secret_key
    export
    export_path
    export_file

    Returns
    -------
    None
    """

    if community is None:
        custom_exit("Execution error: the snmp community is not specified.\n")
    else:
        if export is True:
            click.echo('Exportation activated. Assets will not sent online...')

        try:
            hosts = get_snmp_hosts(device, use_range, range_start, range_end)
        except Exception as e:
            custom_exit(f"Execution error: {e}")
        report = asyncio.run(getting_stacks_by_host_snmp(sorted(hosts), community))
        with open("data", "w+") as file:
            file.write("%s" % report)
        file.close()

        if export is True:
            full_path = Path(export_path) / export_file
            export_network_data_to_csv("data", full_path)
            custom_exit(f'Successfully exported assets to file {full_path}')
        else:
            format_json_report(client_id, secret_key, "data")


@click.command(cls=WatchmanCLI)
def cli():
    pass


@cli.group(name="configure", help='Save configuration variables to the config file')
def configure():
    pass


@configure.command(name="display", help='Display configuration')
def configure_display():
    config = Configuration.load(config_file_path=config_file)
    config.read_and_display_config()


@configure.command(name="export", help='Save exportation configuration variables')
@click.option("-a", "--activate", is_flag=True, help="Activate exportation run mode. Default: False if option not set")
@click.option('-p', '--path', type=click.Path(), default=os.path.expanduser('~'),
              help="The path to the export directory. Default: Current user home directory", required=False)
@click.option('-f', '--file-name', type=str, default='watchman_export_assets.csv',
              help="The exportation file name. Default: watchman_export_assets.csv", required=False)
def configure_exportation(activate, path, file_name):
    config = Configuration.load(config_file_path=config_file)
    section = 'runtime'

    if activate:
        config.set_value(section, 'export', value=True)
    else:
        config.set_value(section, 'export', value=False)

    if path:
        config.set_value(section, 'export_path', value=path)
    if file_name:
        config.set_value(section, 'export_file', value=file_name)


@configure.command(name="connect", help='Save connect configuration variables')
@click.option("-m", "--mode", type=str, default='network',
              help="Runtime mode for agent execution [network/agent]. Default: agent", required=False)
@click.option("-c", "--client-id", type=str, help="Client ID for authentication purpose", required=True)
@click.option("-s", "--client-secret", type=str, help="Client Secret for authentication purpose", required=True)
def configure_connect(mode, client_id, client_secret):
    config = Configuration.load(config_file_path=config_file)
    section = 'runtime'

    if mode:
        config.set_value(section, 'mode', value=mode)

    if client_id:
        config.set_value(section, 'client_id', value=client_id)

    if client_secret:
        config.set_value(section, 'secret_key', value=client_secret)

    if client_secret:
        config.set_value(section, 'secret_key', value=client_secret)


@configure.command(name="network", help='Save network configuration variables')
@click.option("-r", "--use-range", is_flag=True, help="Use target ip address range instead of cidr.")
@click.option("-t", "--network-target", type=IpType(), help="The network target ip address.", required=False)
@click.option("-rs", "--range-start", type=IpType(), help="The network target range start ip address.", required=False)
@click.option("-re", "--range-end", type=IpType(), help="The network target range end ip address.", required=False)
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
def configure_network(snmp_community, snmp_port, network_target, cidr, use_range, range_start, range_end, exempt,
                      snmp_auth_key, snmp_priv_key, snmp_user):
    config = Configuration.load(config_file_path=config_file)
    section = 'network'
    if snmp_community:
        config.set_value(section, 'snmp', 'v2', 'community', value=snmp_community)

    if snmp_user:
        config.set_value(section, 'snmp', 'v3', 'user', value=snmp_user)

    if snmp_auth_key:
        config.set_value(section, 'snmp', 'v3', 'auth_key', value=snmp_auth_key)

    if snmp_priv_key:
        config.set_value(section, 'snmp', 'v3', 'priv_key', value=snmp_priv_key)

    if use_range:
        config.set_value(section, 'use_range', value=True)
        if None in [range_end, range_start]:
            custom_exit(
                "\nPlease add network ip address range parameters! \nNeeded Options: --range-start, --range-end\nSee --help for how to configure network options.")
    else:
        config.set_value(section, 'use_range', value=False)

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
        """ config.set_value(section, 'snmp', 'v2', 'port', value=snmp_port)
        config.set_value(section, 'snmp', 'v3', 'port', value=snmp_port)"""

    if network_target:
        config.set_value(section, 'ip', value=network_target)

    if range_start:
        config.set_value(section, 'range_start', value=range_start)

    if range_end:
        config.set_value(section, 'range_end', value=range_end)

    if cidr:
        config.set_value(section, 'cidr', value=cidr)


@configure.command(name="schedule", help='Save schedule configuration variables')
@click.option("-m", "--minute", type=int, help="Execution every minute. Default: 15", required=True)
@click.option("-h", "--hour", type=int, help="Execution every hour.", required=False)
@click.option("-d", "--day", type=int, help="Execution every day.", required=False)
@click.option("-mo", "--month", type=int, help="Execution every month.", required=False)
def configure_schedule(minute, hour, day, month):
    config = Configuration.load(config_file_path=config_file)
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
    config = Configuration.load(config_file_path=config_file)
    mode = config.get_value('runtime', 'mode', default='network')
    export = config.get_value('runtime', 'export', default=False)
    export_path = config.get_value('runtime', 'export_path', default=os.path.expanduser('~'))
    export_file = config.get_value('runtime', 'export_file', default='watchman_export_assets.csv')
    client_id = config.get_value('runtime', 'client_id', default=None)
    secret_key = config.get_value('runtime', 'secret_key', default=None)
    if None in [mode, client_id, secret_key]:
        click.echo("\nPlease configure agent connect parameters! Check help to see how to configure.")

    community = config.get_value('network', 'snmp', 'v2', 'community', default='public')
    network = config.get_value('network', 'ip')
    use_range = config.get_value('network', 'use_range', default=False)
    range_start = config.get_value('network', 'range_start')
    range_end = config.get_value('network', 'range_end')

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
            custom_exit("\nAuthentication failed!!")
    except requests.exceptions.RequestException as e:
        request_error(error=e)
    try:
        if keyring.get_password("watchmanAgent", "token") is None:
            custom_exit("Authentication failed!!")
    except NoKeyringError as e:
        # use db method
        with KeyDB(table_name="watchmanAgent",
                   db=str(Path(__file__).resolve().parent) + "/" + "watchmanAgent.db") as obj:
            if obj.read_value("token") is None:
                custom_exit("Authentication failed!!")
    """
        Getting stacks from the target 
    """
    if mode == 'agent':
        run_mode_agent(client_id=client_id, secret_key=secret_key, export=export, export_path=export_path,
                       export_file=export_file)
    else:
        run_mode_network(community=community, device=network, use_range=use_range, range_start=range_start,
                         range_end=range_end, client_id=client_id, secret_key=secret_key, export=export,
                         export_path=export_path, export_file=export_file)


if __name__ == "__main__":
    cli()
