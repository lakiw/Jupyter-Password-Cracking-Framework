"""
Shared functions for loading the configuration (e.g. config.yml)

Goal is to not to have to modify anything in this file
during a contest or password cracking session.

YAML was picked as the config filetype since I want to easily
enable 0 or more instances for a lot of the config settings
(such as challenge files, other cracking computers, etc)
"""


import yaml


def load_config(config_name):
    """
    Responsible for the intial loading of the notebook's config.
    Keeping this simple so additional contest specific logic can be
    included in other easier to highlight functions
    
    Returns:
        config_info: (Dictionary) Contains the yaml file as a dictionary
    """

    try:
        config_info = yaml.safe_load(open(config_name))
    except Exception as msg:
        print(f"Exception encounted when trying to read the notebook's config file: {msg}")
        return None
        
    return config_info
