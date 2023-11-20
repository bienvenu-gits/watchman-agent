from setuptools import setup, find_namespace_packages, find_packages

setup(
    name="watchman-agent",
    version="2.0",
    author="Watchman",
    author_email="support@watchman.bj",
    # description = "Watchman Agent 1.0.0",
    packages=["watchman_agent"],
    python_requires='>=3.8',
    include_package_data=True,
    package_data={
        "watchman_agent": [
            "commands/*",  # Inclut tous les fichiers du sous-répertoire 'commands'
        ],
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
