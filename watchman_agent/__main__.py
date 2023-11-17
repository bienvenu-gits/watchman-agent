import ipaddress
import json
import os
import yaml
import configparser
import platform
from functools import cached_property
from pathlib import Path
import click
import keyring
from crontab import CronTab
from keyring.errors import NoKeyringError
from sqlitedict import SqliteDict


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



def first_run():
    try:
        if keyring.get_password("watchmanAgent", "first_run"):
            return False
        else:
            return True
    except NoKeyringError:
        # use db method
        obj = KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "watchmanAgent.db")
        if obj.read_value("first_run") is None:
            return True
        else:
            return False


class CronJob:
    _jobs = []

    def __init__(self):
        self.os_current_user = os.getlogin()
        self.cron = CronTab(user=self.os_current_user)

    def new_job(self, command, comment, hour=None, minute=None, day=None):
        job = self.cron.new(command=command, comment=comment)

        if hour:
            job.hour.every(hour)
        elif minute:
            job.minute.every(minute)
        elif day:
            job.day.every(day)
        else:
            job.hour.every(2)

        job.enable()
        job.every_reboot()
        self.cron.write()
        self._jobs.append(job)
        return True

    def del_job(self, job):
        return self._jobs.pop(job)

    @cached_property
    def all(self):
        return self._jobs


@click.group()
def cli() -> None:
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
# def connect(network_mode, client_id, secret_key, community, ip_network, device):
    cfg = Configuration()
    config = cfg.create(config_file_path='config.yml')

    network_mode = config.get_value('runtime', 'mode', default='network')
    client_id = config.get_value('runtime', 'client_id')
    secret_key = config.get_value('runtime', 'secret_key')
    if None in [network_mode, client_id, secret_key]:
        click.echo("\nPlease configure agent! Check help to see how to configure.")

    community = config.get_value('network', 'snmp', 'v2', 'community', default='public')
    ip_network = config.get_value('network', 'ip')
    target_address = ip_network
    with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "watchmanAgent.db") as r_obj:
        read_obj = r_obj
    with KeyDB(table_name="watchmanAgent",
               db=str(Path(__file__).resolve().parent) + "watchmanAgent.db", mode="write") as w_obj:
        write_obj = w_obj

    if first_run():
        try:
            keyring.set_password("watchmanAgent", "client", client_id)
            keyring.set_password("watchmanAgent", "secret", secret_key)
        except NoKeyringError:
            # use the db instead
            write_obj.insert_value("client", client_id)
            write_obj.insert_value("secret", secret_key)

        if platform.system() == 'Windows':
            env_path = str(Path(__file__).resolve().parent) + "\commands\dist\.env"
            if not network_mode:
                os.system(
                    str(Path(
                        __file__).resolve().parent) + f"\commands\dist\main.exe {client_id} {secret_key} {env_path}")
                cron = CronJob()
                cron.new_job(command=f"watchman-agent connect {client_id} {secret_key}", comment="agentRunFirst")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          f"\commands\dist\main.exe --network-mode -c {community} -d {target_address} {client_id} {secret_key} {env_path}")

                cron = CronJob()
                cron.new_job(
                    command=f"watchman-agent connect --network-mode -c {community} -d {target_address} {client_id} {secret_key}",
                    comment="agentRun")
        else:
            env_path = str(Path(__file__).resolve().parent) + "/commands/dist/.env"

            if not network_mode:
                os.system(
                    str(Path(__file__).resolve().parent) + f"/commands/dist/main {client_id} {secret_key} {env_path}")
                cron = CronJob()
                cron.new_job(
                    command=f"watchman-agent connect {client_id} {secret_key}", comment="agentRun")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          f"/commands/dist/main --network-mode -c {community} -d {target_address} {client_id} {secret_key} {env_path}")
                cron = CronJob()
                cron.new_job(
                    command=f"watchman-agent connect --network-mode -c {community} -d {target_address} {client_id} {secret_key}",
                    comment="agentRun")
    else:
        try:
            stored_client = keyring.get_password("watchmanAgent", "client")
            stored_secret = keyring.get_password("watchmanAgent", "secret")
        except NoKeyringError:
            # we use db
            stored_client = read_obj.read_value("client")
            stored_secret = read_obj.read_value("secret")

        client = client_id if client_id else stored_client
        secret = secret_key if secret_key else stored_secret

        if platform.system() == 'Windows':
            env_path = str(Path(__file__).resolve().parent) + "\commands\dist\.env"
            if not network_mode:
                os.system(
                    str(Path(__file__).resolve().parent) + f"\commands\dist\main.exe {client} {secret} {env_path}")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          f"\commands\dist\main.exe --network-mode -c {community} -d {target_address} {client} {secret} {env_path}")
        else:
            env_path = str(Path(__file__).resolve().parent) + "/commands/dist/.env"

            if not network_mode:
                os.system(str(Path(__file__).resolve().parent) + f"/commands/dist/main {client} {secret} {env_path}")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          f"/commands/dist/main --network-mode -c {community} -d {target_address} {client} {secret} {env_path}")


cli.add_command(configure_connect)
cli.add_command(configure_network)
cli.add_command(configure_schedule)
cli.add_command(run)

if __name__ == "__main__":
    cli()
