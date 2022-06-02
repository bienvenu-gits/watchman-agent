from setuptools import setup

setup(
    name="watchman-agent",
    version="1.1.3",
    # author = "Flobert Gantua" ,
    # author_email = "fgantua32@gmail.com",
    # description = "Watchman Agent 1.0.0",
    # packages=["watchman_agent","watchman_agent/commands"],

    package_data={
        "watchman_agent":["commands/dist/main","commands/dist/main.exe","commands/dist/.env"]
    },

    # entry_points={  # Optional
    #     "console_scripts": [
    #         "watchman-agent=watchman_agent.__main__:main",
    #     ],
        
    #   },

)