"""
Contains functions that will likely need to be changed
per contest or cracking session

For example, this contains logic for how to load up
the challenge hashes
"""


import yaml

# Local imports
from .hash_fingerprint import hash_fingerprint
from .hash import Hash


def load_challenge_files(details, hash_list):
    """
    Top level function responsible for loading the hashes from a file

    Eventually I'd like to have a plugin functionality so people
    don't need to update this function, but for now you'll need
    to add a reference to the logic to load a hash file here

    Inputs:
        details: (DICT) Contains info needed to load the challenge file

        hash_list: (HashList) Place to store the hashes being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hash
    """

    try:
        if details['format'] == 'cmiyc_2023':
            return _load_cmiyc_2023(details, hash_list)
        
        else:
            print(f"Error, format {details['format']} not supported. Add it to challenge_specific_functions.py")
            return False

    except Exception as msg:
        print(f"Error loading the challenge file: {msg}")
        return False
    

def _load_cmiyc_2023(details, hash_list):
    """
    Loads the challenge file from the cmiyc 2023 contest

    Inputs:
        details: (DICT) Contains info needed to load the challenge file

        hash_list: (HashList) Place to store the hashes being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hashes
    """
    print("Starting to load challenge yaml file. This may take a minute or two")
    raw_values = yaml.safe_load(open(details['file']))

    # This challenge had raw-MD5, raw-sha1, and raw-sha256
    length_helper = {
        32:"raw-md5",
        40:"raw-sha1",
        64:"raw-sha256",
    }

    for user_list in raw_values['users']:
        for username, user_info in user_list.items():
            hash_info = hash_fingerprint(user_info['PasswordHash'], length_helper)
            if not hash_info:
                print(f"Error, passed invalid length helper to the hash_fingerprint function: {length_helper}")
                raise Exception

            # Add the type if it hasn't been encountered before
            hash_list.add_type(
                type=hash_info['type'],
                jtr_mode=hash_info['jtr_mode'],
                hc_mode=hash_info['hc_mode'],
                cost=hash_info['cost']
            )

            # Save the metadata
            metadata = {}
            for item, value in user_info.items():
                if item != "PasswordHash":
                    metadata[item] = value

            # Save the hash
            hash = Hash(
                orig_hash=user_info['PasswordHash'],
                type=hash_info['type'],
                jtr_hash=hash_info['jtr_hash'],
                hc_hash=hash_info['hc_hash'],
                submit_hash=user_info['PasswordHash'],
                source=details['file'],
                username=username,
                metadata=metadata
            )
            hash_list.add(hash)

    return True