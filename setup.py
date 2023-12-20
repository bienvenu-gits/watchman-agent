from setuptools import setup, find_packages

setup(
    name="watchman-agent",
    version="2.0.6",
    author="Watchman",
    author_email="support@watchman.bj",
    # description = "Watchman Agent 1.0.0",
    packages=find_packages(
        where='watchman_agent',
        include=['watchman_agent.*']
    ),
    python_requires='>=3.8',
    include_package_data=True,
    # py_modules=[''],
    package_data={
        "watchman_agent": ["commands/**/*", "commands/*", "commands/dist/*", "commands/dist/*.env"]
    },
    # data_files=[('commands/dist', ['commands/dist/main_darwin', 'commands/dist/main.exe', 'commands/dist/main_linux', 'commands/dist/.env'])],
    install_requires=[
        'requests',
        'sqlitedict',
        'scapy',
        'keyring',
        'python-crontab',
        'environs',
        'click',
        'sqlitedict',
        'paramiko',
        'pyyaml',
        'schedule',
        'pysnmplib',
        'semver',
        'packaging',
        'openpyxl',
        # 'pandas',
        'getmac',
    ],

    # entry_points={  # Optional
    #     "console_scripts": [
    #         "watchman-agent=watchman_agent.__main__:cli",
    #     ],
    #
    # },

)
