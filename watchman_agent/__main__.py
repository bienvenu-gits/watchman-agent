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

watchmanAgentDb = "watchmanAgent.db"
configYml = "config.yml"

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


def first_run():
    try:
        if keyring.get_password("watchmanAgent", "first_run"):
            return False
        else:
            return True
    except NoKeyringError:
        # use db method
        obj = KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + watchmanAgentDb)
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


# @click.group()
# def cli() -> None:
#     pass

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
    config = cfg.create(config_file_path=configYml)
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
    config = cfg.create(config_file_path=configYml)
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
    config = cfg.create(config_file_path=configYml)
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
    config = cfg.create(config_file_path=configYml)

    network_mode = config.get_value('runtime', 'mode', default='network')
    client_id = config.get_value('runtime', 'client_id')
    secret_key = config.get_value('runtime', 'secret_key')
    if None in [network_mode, client_id, secret_key]:
        click.echo("\nPlease configure agent! Check help to see how to configure.")

    community = config.get_value('network', 'snmp', 'v2', 'community', default='public')
    ip_network = config.get_value('network', 'ip')
    target_address = ip_network
    with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + watchmanAgentDb) as r_obj:
        read_obj = r_obj
    with KeyDB(table_name="watchmanAgent",
               db=str(Path(__file__).resolve().parent) + watchmanAgentDb, mode="write") as w_obj:
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
                        __file__).resolve().parent) + "\commands\dist\main.exe run")
                cron = CronJob()
                cron.new_job(command=f"watchman-agent connect {client_id} {secret_key}", comment="agentRunFirst")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          "\commands\dist\main.exe run")

                cron = CronJob()
                cron.new_job(
                    command="watchman-agent run",
                    comment="agentRun")
        else:
            env_path = str(Path(__file__).resolve().parent) + "/commands/dist/.env"

            if not network_mode:
                os.system(
                    str(Path(__file__).resolve().parent) + "/commands/dist/main run")
                cron = CronJob()
                cron.new_job(
                    command=f"watchman-agent connect {client_id} {secret_key}", comment="agentRun")
            else:
                os.system(str(Path(__file__).resolve().parent) +
                          "/commands/dist/main run")
                cron = CronJob()
                cron.new_job(
                    command="watchman-agent run",
                    comment="agentRun")
    else:
        if platform.system() == 'Windows':
            env_path = str(Path(__file__).resolve().parent) + "\commands\dist\.env"
            os.system(str(Path(__file__).resolve().parent) +
                      "\commands\dist\main.exe run")
        else:
            env_path = str(Path(__file__).resolve().parent) + "/commands/dist/.env"
            os.system(str(Path(__file__).resolve().parent) +
                          "/commands/dist/main run")


cli.add_command(configure_connect)
cli.add_command(configure_network)
cli.add_command(configure_schedule)
cli.add_command(run)

if __name__ == "__main__":
    cli()
