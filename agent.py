import ipaddress
from functools import cached_property
from typing import Optional, NoReturn

import click
import keyring
from crontab import CronTab
from environs import Env

# Fetch Variables environment
env = Env()
env.read_env()
ENV = env("ENV_MODE")

WEBHOOK_URL = env("WEBHOOK_URL")
CONNECT_URL = env("CONNECT_URL")

if ENV == "development":
    WEBHOOK_URL = env("DEV_WEBHOOK_URL")
    CONNECT_URL = env("DEV_CONNECT_URL")


def on_error(message: str, error: Optional[Exception] = None, code=-1) -> NoReturn:
    """Render an error message then exit the app."""

    if error:
        error_text = Text(message)
        error_text.stylize("bold red")
        error_text += ": "
        error_text += error_console.highlighter(str(error))
        error_console.print(error_text)
    else:
        error_text = Text(message, style="bold red")
        error_console.print(error_text)
    sys.exit(code)


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
    if keyring.get_password("watchmanAgent", "first_run"):
        return False
    return True


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
def cli():
    pass


@click.command()
@click.option('--network-mode', is_flag=True, help='Run in network mode')
@click.option("-c", "--community", type=str, default="public",
              help="SNMP community used to authenticate the SNMP management station.", required=0)
@click.option("-t", "--target", type=IP(), help="The network ip address or the device ip address.")
@click.argument("client-id", type=str, required=1)
@click.argument("secret-key", type=str, required=1)
def connect(network_mode, community, target,  client_id, secret_key):
    pass


@click.command()
def local():
    pass


@click.command()
def network():
    pass


cli.add_command(connect)
cli.add_command(local)
cli.add_command(network)
