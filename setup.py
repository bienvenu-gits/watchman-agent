from setuptools import setup, find_namespace_packages

setup(
    name="watchman-agent",
    version="1.2.5",
    author="Watchman",
    author_email="support@watchman.bj",
    # description = "Watchman Agent 1.0.0",
    packages=find_namespace_packages(
        where=['watchman_agent', 'watchman_agent.*']
    ),
    python_requires='>=3.8',
    include_package_data=True,
    # py_modules=[''],
    package_data={
        "watchman_agent": ["commands/*"]
    },
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
    ],

    # entry_points={  # Optional
    #     "console_scripts": [
    #         "watchman-agent=watchman_agent.__main__:cli",
    #     ],
    #
    # },

)
