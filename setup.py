from setuptools import setup, find_packages

setup(
    name="watchman-agent",
    version="2.2.2",
    author="Watchman",
    author_email="support@watchman.bj",
    # description = "Watchman Agent 1.0.0",
    packages=find_packages(
        where='watchman_agent',
        include=['watchman_agent.*']
    ),
    python_requires='>=3.8',
    # py_modules=[''],
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
        'platformdirs',
    ],

    entry_points='''
        [console_scripts]
        watchman-agent=watchman_agent.__main__:cli
    '''
)
