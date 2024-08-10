"""
Contains functions that will likely need to be changed
per contest or cracking session

For example, this contains logic for how to load up
the challenge hashes
"""


import yaml

# Local imports
from .hash_fingerprint import hash_fingerprint
from .hash_fingerprint import get_len_for_type


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
        # If the file is just a list of all the same hash types with no additional other data
        if details['format'] == 'plain_hash':
            return _load_plain_hash(details, hash_list, target_list)
        elif details['format'] == 'cmiyc_2023':
            return _load_cmiyc_2023(details, hash_list, target_list)
        elif details['format'] == 'mixed_list_with_usernames':
            return _load_mixed_list_with_usernames(details, hash_list, target_list)
        else:
            print(f"Error, format {details['format']} not supported. Add it to challenge_specific_functions.py")
            return False

    except Exception as msg:
        print(f"Error loading the challenge file: {msg}")
        return False
    
def _load_plain_hash(details, hash_list, target_list):
    """
    Loads a list of plain password hashes. All hashes are expected to be of the
    same format. No usernames or other metadata is expected to be in this list

    Inputs:
        details: (DICT) Contains info needed to load the hash files

        hash_list: (HashList) Place to store the hashes being loaded

        target_list: (TargetList) Place to store the targets being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hashes
    """
    print(f"Starting to load challenge file: {details['file']}. This may take a minute or two")

    hash_type = None
    length_helper = {}

    # Used to create a target that has all of these hashes
    target_hash_id_list = []

    # Check to see if the hash type is defined, and if it needs a length helper for it
    # Aka a lot of 128 bit hashes look the same
    if 'type' in details:
        hash_type = details['type']
        hash_length = get_len_for_type(hash_type)
        if hash_length:
            length_helper[hash_length] = hash_type

    with open(details['file']) as challenge_file:
        lines = challenge_file.readlines()
        for line in lines:
            
            # Remove trailing whitespace and newlines
            line = line.strip()
            
            # Skip blank lines
            if len(line) == 0:
                continue

            # Perform a sanity check to make sure the hash looks legit
            hash_info = hash_fingerprint(line, length_helper)

            if not hash_info['type']:
                print(f"Warning: Unsupported Hash: {line}")
            if hash_type and (hash_info['type'] != hash_type):
                print(f"Warning: the hash type from autodetection identifies the hash as {hash_info['type']} when the config specified {details['type']}")

            # Add the type
            # If the type has been added before this will not make any changes
            hash_list.add_type(
                type=hash_info['type'],
                jtr_mode=hash_info['jtr_mode'],
                hc_mode=hash_info['hc_mode'],
                cost=hash_info['cost']
            )

            # Perform further normalization for certain file encryption hashes
            if hash_info['type'] == "pkzip":
                split_line = line.split('$pkzip')[1]
                line = f"$pkzip{split_line.split('pkzip$')[0]}pkzip$"

            # Save the hash
            hash_list.add(line, type=hash_info['type'])

            # Create a target/metadata for this list
            hash_index = hash_list.hash_lookup[line]
            if hash_index not in target_hash_id_list:
                target_hash_id_list.append(hash_index)

    if 'source' in details:
        target_list.add(metadata={'source':details['source']}, hashes=target_hash_id_list)

    print("Done loading the challenge file.")
    return True


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
        34:"striphash33",
        34:"striphash34",
        35:"striphash35",
        36:"striphash36",
        37:"striphash37",
        38:"striphash38",
        39:"striphash39",
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


def _load_mixed_list_with_usernames(details, hash_list, target_list):
    """
    Loads from a list that has multiple hash types stored in it, one per line
    These hashes also have a username in front of them

    Inputs:
        details: (DICT) Contains info needed to load the challenge file

        hash_list: (HashList) Place to store the hashes being loaded

        target_list: (TargetList) Place to store the targets being loaded

    Returns:
        True: The hash file was loaded sucessfully

        False: An error occured loading the hashes
    """
    print(f"Starting to load challenge file: {details['file']}. This may take a minute or two")

    hash_type = None
    length_helper = {}

    # Used to create a target that has all of these hashes
    target_hash_id_list = []

    # Check to see if the hash type is defined, and if it needs a length helper for it
    # Aka a lot of 128 bit hashes look the same
    if 'hash_types' in details:
        for hash_type in details['hash_types']:
            hash_length = get_len_for_type(hash_type)
            if hash_length:
                length_helper[hash_length] = hash_type

    with open(details['file']) as challenge_file:
        lines = challenge_file.readlines()
        for line in lines:
            
            # Remove trailing whitespace and newlines
            line = line.strip()
            
            # Skip blank lines
            if len(line) == 0:
                continue

            # Split the username and the password hash
            split_list = line.split(":",1)
            if len(split_list) != 2:
                print(f"Warning: Missing username: {line}")
                username = ""
                hash = split_list[0]
            else:
                username = split_list[0]
                hash = split_list[1]

            # Perform a sanity check to make sure the hash looks legit
            hash_info = hash_fingerprint(hash, length_helper)

            if not hash_info['type']:
                print(f"Warning: Unsupported Hash: {hash}")
            if hash_type and ('hash_types' in details) and (hash_type not in details['hash_types']):
                print(f"Warning: the hash type from autodetection identifies the hash as {hash_info['type']} when the config specified {details['type']}")

            # Add the type
            # If the type has been added before this will not make any changes
            hash_list.add_type(
                type=hash_info['type'],
                jtr_mode=hash_info['jtr_mode'],
                hc_mode=hash_info['hc_mode'],
                cost=hash_info['cost']
            )

            # Save the hash
            hash_list.add(hash, type=hash_info['type'])

            # Create a target/metadata for this list
            hash_index = hash_list.hash_lookup[hash]
            metadata = {'username':username}
            if 'source' in details:
                metadata['source'] = details['source']
            target_list.add(metadata=metadata, hashes=[hash_index])

    print("Done loading the challenge file.")
    return True


