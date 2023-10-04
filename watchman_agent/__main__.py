import ipaddress
import json
import os
import platform
from functools import cached_property
from pathlib import Path
import click
import keyring
from crontab import CronTab
from keyring.errors import NoKeyringError
from sqlitedict import SqliteDict


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


class IP(click.ParamType):
    name = "ip"

    def convert(self, value, param, ctx):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as e:
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


@cli.command()
@click.option('--network-mode', is_flag=True, help='Run in network mode')
@click.option("-c", "--community", type=str, default="public",
              help="SNMP community used to authenticate the SNMP management station.", required=0)
@click.option("-n", "--ip-network", type=IP(), help="The network ip address.")
@click.option("-d", "--device", type=IP(), help="The device ip address.")
@click.argument("client-id", type=str, required=1)
@click.argument("secret-key", type=str, required=1)
def connect(network_mode, client_id, secret_key, community, ip_network, device):
    target_address = ip_network or device
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


cli.add_command(connect)

if __name__ == "__main__":
    cli()
