"""
Shared functions for loading the configuration (e.g. config.yml)

Goal is to not to have to modify anything in this file
during a contest or password cracking session.

YAML was picked as the config filetype since I want to easily
enable 0 or more instances for a lot of the config settings
(such as challenge files, other cracking computers, etc)
"""


import yaml


def is_valid_config_key(key):
    """
    Makes sure the top level keys are valid for the config file

    This will need to be updated if new keys are added to the config file.
    Also, only checking the top level key for now. This is more of a quick
    sanity check vs. a strong checking.
    
    Inputs:
        key: (String) The key to check

    Returns:
        True: (bool) If this is a valid key

        False: (bool) This is not a valid key
    """
    valid_keys = [
        'jtr_config',
        'hashcat_config',
        'session_management',
        'challenge_files',
        'score_info',
    ]

    if key in valid_keys:
        return True
    return False


def load_config(config_name, ignore_errors=False):
    """
    Responsible for the intial loading of the notebook's config.
    Keeping this simple so additional contest specific logic can be
    included in other easier to highlight functions
    
    Returns:
        config_info: (Dictionary) Contains the yaml file as a dictionary
    """

    try:
        with open(config_name) as config_file:
            config_info = yaml.safe_load(config_file)
    except Exception as msg:
        print(f"Exception encounted when trying to read the notebook's config file: {msg}")
        return {}

    # If a string is returned from yaml.safe_load it's not valid yaml
    if type(config_info) == str:
        print(f"Error: The file: {config_name} does not look like valid YAML")
        return {}
    
    # Check to make sure the top level keys are valid
    for key in config_info.keys():
        if not is_valid_config_key(key):
            print(f"Error: The key: {key} in the config file is not valid. Exiting")
            return {}
    return config_info
