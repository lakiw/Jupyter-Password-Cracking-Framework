"""
Parent class for jtr_mgr and hc_mgr

I found I was repeating 99% of the code between the two.
Longer term I expect there to be some differences if I
ever add in some basic attacks (such as loopback), or
in JtR's case I want to make use of it's --left command
line feature. So I'm going with inheritance even
though I may never get around to using that functionality
"""

# Local imports
from .hash_fingerprint import hash_fingerprint

class PWCrackerMgr:
    """
    Base functionality for keeping track of 
    cracked passwords and syncing pot files
    """

    def __init__(self, config):
        self.path = None
        if 'path' in config:
            self.path = config['path']

        self.main_pot_file = None
        if 'main_pot_file' in config:
            self.main_pot_file = config['main_pot_file']

        self.additional_pot_files = []
        if 'additional_pot_files' in config:
            self.additiona_pot_files = config['additional_pot_files']

        # Set cracker specific variables (default is JtR since I'm biased)
        self.pot_extension = ".pot"
        self.hash_type = "jtr_hash"
        self.name = "Generic Password Cracking Class"

    def is_potfile(self, filename):
        """
        A couple of quick sanity checks to see if a file looks like a potfile

        I'm sure there are obmissions and errors with my logic since there
        may be hash types that don't follow the format I expect

        Inputs:
            filename: (String) The name and path of the file to open

        Returns:
            True: It looks like a potfile

            False: It does not look like a potfile
        """
        # Check the file extension
        if not filename.endswith(self.pot_extension):
            print(f"Error, the potfile {filename} does not end with {self.pot_extension}")
            print(f"Exiting out to avoid corrupting any potential hashes or files")
            return False
        
        # Open the potfile and check the first 10 lines to see if they look like
        # cracked hashes. This is a very, very naive check, just looking for a ":"
        checked_lines = 0
        try:
            with open(filename) as potfile:

                # Reading in the lines this way to make unit tests easier with mock
                lines = potfile.readlines()
                for line in lines:
                    checked_lines += 1
                    hash, divider, plain = line.partition(":")
                    if not plain:
                        print(f"Exception, the file {filename} did not look like a potfile")
                        print(f"Offending line: {line}")
                        return False
                    if checked_lines > 10:
                        break
        except Exception as msg:
            print(f"Exception when trying to open the {self.name} pot file: {filename} : {msg}")
            return False
        return True

    def load_potfile(self, filename, hash_list, update_only=True):
        """
        Loads in newly cracked hashes into hash_list

        Inputs:
            filename: (String) The potfile to load

            hash_list: (HashList) The list of hashes to update

            update_only: (Bool) If true, will skip loading new hashes if they
            are not already in hash_list. This is to help if you have the results
            of another password cracking session in your potfile and don't want to mess
            up your analysis of your current session.

        Returns:
            new_cracks: (Int) The number of newly cracked passwords

            -1: If a problem occured
        """
        # Check that it looks like a potfile first
        if not self.is_potfile(filename):
            print(f"Can not load potfile {filename} since it did not look like a potfile")
            return -1

        new_cracks = 0
        try:
            with open(filename) as potfile:
                lines = potfile.readlines()
                for line in lines:
                    hash, divider, plain = line.partition(":")

                    # Normalize the hash to remove any passwor cracker specific
                    # formatting
                    hash = self.normalize_hash(hash)
                    
                    # Remove newlines from the plaintext
                    plain = plain.rstrip('\r\n')

                    if update_only:
                        # Add cracks/plaintext to the hash
                        new_cracks += hash_list.update(hash,plaintext=plain)
                    else:
                        # Add the hash
                        # If the hash has already been added/cracked nothing changes

                        # Identify the hash type in case it needs to be added
                        # Not using length helper since there's too big a chance it might
                        # misidentify hashes from other cracking sessions. Aka you might
                        # be adding an MD4 hash
                        #
                        # In the future, might add JtR dynamic fields to hash_fingerprint in
                        # which case it might make sense to do this on the raw hash vs. the normalized one
                        hash_info = hash_fingerprint(hash)
                        if hash_info['type']: 
                            new_cracks += hash_list.add(hash,plaintext=plain, type=hash_info['type'])
                        else:
                            new_cracks += hash_list.add(hash,plaintext=plain)

        except Exception as msg:
            print(f"Exception when trying to parse the pot file: {msg}")
            return -1
    
        return new_cracks

    def update_potfile(self, filename, hash_list):
        """
        Updates a potfile. Unsafe to call directly
        if you accidentally specify the wrong file

        I'm adding in some checks to see if the file we're
        updating looks like a potfile, but I wouldn't
        count on them 100%

        Inputs:

            filename: (String) The name of the potfile to update

            hash_list: (HashList) The list of hashes to update

        Returns:
            new_cracks: (Int) The number of newly cracked passwords

            -1: If a problem occured
        """
        new_cracks = 0

        try:
            # First create a quick hash lookup of cracked passwords so we can
            # then quickly identify missing passwords we need to add
            pot_lookup = {}
            with open(filename) as potfile:
                lines = potfile.readlines()
                for line in lines:
                    hash, divider, plain = line.partition(":")

                    # Remove newlines from the plaintext
                    plain = plain.rstrip('\r\n')

                    # Need to do things like strip out password cracker specific
                    # storage techniques for hashes
                    standard_hash = self.normalize_hash(hash)
                    if not standard_hash:
                        print(f"Skipping loading malformed hash")
                        continue

                    if standard_hash in pot_lookup:
                        print(f"Warning, you have duplicate hashes in your potfile {filename}: {hash}:{plain}")
                    else:
                        pot_lookup[standard_hash] = plain

            # Now go through all the cracked hashes and see if any are missing
            # If so, append them to the pot file.
            with open(filename, mode='a') as potfile:
                for index, cur_hash in hash_list.hashes.items():

                    # Don't add hashes of unknown type to the pot files since that might add junk
                    # that the crackers can't handle.
                    if cur_hash.plaintext and cur_hash.hash not in pot_lookup and hash_list.type_lookup[index] != hash_list.unknown_type:
                        # Need to add a sanity check if a particular hash isn't supported by the
                        # cracking program)
                        formatted_hash = self.format_hash(cur_hash.hash, hash_list.type_lookup[index])
                        if formatted_hash:
                            new_cracks += 1
                            potfile.write(f"{formatted_hash}:{cur_hash.plaintext}\n")
                    # Quick sanity check to make sure the plains match
                    # Hopefully this can help catch data corruption if it is happening
                    elif cur_hash.hash in pot_lookup and cur_hash.plaintext:
                        if pot_lookup[cur_hash.hash] != cur_hash.plaintext:
                            print(f"Warning, the hash {cur_hash.hash} in the potfile has a different plaintext then in the cracked list")
                            print(f"Potfile_Plaintext:{pot_lookup[cur_hash.hash]}")
                            print(f"Main_Hashlist_Plaintext:{cur_hash.plaintext}")
        except Exception as msg:
            print(f"Exception when trying to parse {self.name} pot file: {msg}")
            return -1
    
        return new_cracks

    def normalize_hash(self, hash):
        """
        Stub function for any normalization to convert from a password cracker
        hash format to a "normalized" format used by this analysis platform

        For example, remove the $dynamic_X$ prefix of JtR hashes. Those are
        super helpful but that info is kept in the type_lookup datastructure of
        HashList().

        Inputs:
            hash: (str) The password hash to normalize

        Returns:
            normalized_hash: (str) The normalized verion of the hash
        """
        return hash
    
    def format_hash(self, hash, type):
        """
        Stub function for any support to convert from a normalized hash to
        the format the password cracker expects in the pot file

        For example, add the $dynamic_X$ prefix of JtR hashes.

        Inputs:
            hash: (str) The password hash to normalize

            type: (str) The type to format this hash as

        Returns:
            normalized_hash: (str) The normalized verion of the hash
        """
        return hash