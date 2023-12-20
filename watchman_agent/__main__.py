import ipaddress
import json
import os
import platform
import subprocess
from functools import cached_property
from pathlib import Path
import click
import keyring
from crontab import CronTab
from keyring.errors import NoKeyringError
from sqlitedict import SqliteDict

watchmanAgentDb = "watchmanAgent.db"
configYml = "config.yml"


def run_cli_command(command):
    os = platform.system().lower()
    if os in ['linux', 'darwin']:
        path = "" + str(Path(__file__).resolve().parent) + f"/commands/dist/main_{os}"
        c = [path]
        c.extend(command.split())
        subprocess.run(c, shell=False)
    else:
        path = str(Path(__file__).resolve().parent) + "/commands/dist/main.exe"
        c = [path]
        c.extend(command.split())
        subprocess.run(c, shell=False)


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


@configure.command(name="export", help='Save exportation configuration variables')
@click.option("-a", "--activate", type=click.BOOL, default=False,
              help="Activate exportation run mode. Default: False if option not set", required=False)
@click.option('-p', '--path', type=click.Path(), default=os.path.expanduser('~'),
              help="The path to the export directory. Default: Current user home directory", required=False)
@click.option('-f', '--file-name', type=str, default='watchman_export_assets.csv',
              help="The exportation file name. Default: watchman_export_assets.csv", required=False)
def configure_exportation(activate, path, file_name):
    if activate is not None:
        run_cli_command(f'configure export --activate {activate}')
    if path:
        run_cli_command(f'configure export --path {path}')
    if file_name:
        run_cli_command(f'configure export --file-name {file_name}')


@configure.command(name="connect", help='Save connect configuration variables')
@click.option("-m", "--mode", type=str, default='network',
              help="Runtime mode for agent execution [network/agent]. Default: agent", required=False)
@click.option("-c", "--client-id", type=str, help="Client ID for authentication purpose", required=True)
@click.option("-s", "--client-secret", type=str, help="Client Secret for authentication purpose", required=True)
@click.option("-x", "--export", type=str, default=True,
              help="This config is for exporting or not. Default: No", required=False)
@click.option("-xt", "--export_type", type=str, default=True,
              help="This config is for define type of export file. Types: csv, xlsx, json", required=False)
@click.option("-xp", "--export_path", type=str, default='',
              help="This config is for define folder for save file exported. Default: No", required=False)
def configure_connect(mode, client_id, client_secret, export, export_type, export_path):
    if mode or client_id and client_secret:
        run_cli_command(f'configure connect --mode {mode} --client-id {client_id} --client-secret {client_secret} --export {export or None} --export_type {export_type or None} --export_path {export_path or None}')


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
    if snmp_community:
        run_cli_command(f'configure network --snmp-community {snmp_community}')

    if snmp_user:
        run_cli_command(f'configure network --snmp-user {snmp_user}')

    if snmp_auth_key:
        run_cli_command(f'configure network --snmp-auth-key {snmp_auth_key}')

    if snmp_priv_key:
        run_cli_command(f'configure network --snmp-priv-key {snmp_priv_key}')

    if exempt:
        run_cli_command(f'configure network --exempt {exempt}')

    if snmp_port:
        run_cli_command(f'configure network --snmp-port {snmp_port}')

    if network_target:
        run_cli_command(f'configure network --network-target {network_target}')

    if cidr:
        run_cli_command(f'configure network --cidr {cidr}')


@configure.command(name="schedule", help='Save schedule configuration variables')
@click.option("-m", "--minute", type=int, help="Execution every minute. Default: 15", required=True)
@click.option("-h", "--hour", type=int, help="Execution every hour.", required=False)
@click.option("-d", "--day", type=int, help="Execution every day.", required=False)
@click.option("-mo", "--month", type=int, help="Execution every month.", required=False)
def configure_schedule(minute, hour, day, month):
    if minute:
        run_cli_command(f'configure schedule --minute {minute}')

    if hour:
        run_cli_command(f'configure schedule --hour {hour}')

    if day:
        run_cli_command(f'configure schedule --day {day}')

    if month:
        run_cli_command(f'configure schedule --month {month}')


@cli.command(name='run', help='Attach monitoring to cron job and watch for stacks')
def run():
    with KeyDB(table_name="watchmanAgent", db=str(Path(__file__).resolve().parent) + "/" + watchmanAgentDb) as r_obj:
        read_obj = r_obj
    with KeyDB(table_name="watchmanAgent",
               db=str(Path(__file__).resolve().parent) + "/" + watchmanAgentDb, mode="write") as w_obj:
        write_obj = w_obj

    if first_run():
        run_cli_command(f"run")
        cron = CronJob()
        cron.new_job(command=f"watchman-agent run", comment="agentRunFirst")
    else:
        run_cli_command(f"run")


if __name__ == "__main__":
    cli()
