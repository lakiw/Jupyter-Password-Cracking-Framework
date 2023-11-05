"""
Contains functions that will likely need to be changed
per contest or cracking session

For example, this contains logic for how to load up
the challenge hashes
"""


import yaml

# Local imports
from .hash_fingerprint import hash_fingerprint


def load_challenge_files(details, hash_list, target_list):
    """
    Top level function responsible for loading the hashes from a file

    Eventually I'd like to have a plugin functionality so people
    don't need to update this function, but for now you'll need
    to add a reference to the logic to load a hash file here

    Inputs:
        details: (DICT) Contains info needed to load the challenge file

        hash_list: (HashList) Place to store the hashes being loaded

        target_list: (TargetList) Place to store the targets being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hash
    """

    try:
        if details['format'] == 'cmiyc_2023':
            return _load_cmiyc_2023(details, hash_list, target_list)
        
        else:
            print(f"Error, format {details['format']} not supported. Add it to challenge_specific_functions.py")
            return False

    except Exception as msg:
        print(f"Error loading the challenge file: {msg}")
        return False
    

def _load_cmiyc_2023(details, hash_list, target_list):
    """
    Loads the challenge file from the cmiyc 2023 contest

    Inputs:
        details: (DICT) Contains info needed to load the challenge file

        hash_list: (HashList) Place to store the hashes being loaded

        target_list: (TargetList) Place to store the targets being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hashes
    """
    print("Starting to load challenge yaml file. This may take a minute or two")
    with open(details['file']) as challenge_file:
        raw_values = yaml.safe_load(challenge_file)

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
                print(f"Error, likely passed invalid length helper to the hash_fingerprint function: {length_helper}")
                raise Exception

            # Add the type
            # If the type has been added before this will not make any changes
            hash_list.add_type(
                type=hash_info['type'],
                jtr_mode=hash_info['jtr_mode'],
                hc_mode=hash_info['hc_mode'],
                cost=hash_info['cost']
            )

            # Save the hash
            hash_list.add(user_info['PasswordHash'], type=hash_info['type'])
            
            # Get the hash index to add that to the target info
            hash_index = hash_list.hash_lookup[user_info['PasswordHash']]
            
            # Add the target
            metadata = {}
            for key, value in user_info.items():
                # Remove the password hash from target metadata
                if key != 'PasswordHash':
                    metadata[key] = value

            target_list.add(metadata=metadata, hashes=[hash_index])
    print("Done loading the challenge yaml file.")
    return True