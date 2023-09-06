"""
Parent class for jtr_mgr and hc_mgr

I found I was repeating 99% of the code between the two.
Longer term I expect there to be some differences if I
ever add in some basic attacks (such as loopback), or
in JtR's case I want to make use of it's --left command
line feature. So I'm going with inheritance even
though I may never get around to using that functionality
"""

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
                for line in potfile:
                    checked_lines += 1
                    hash, divider, plain = line.partition(":")
                    if not plain:
                        print(f"Exception, the file {filename} did not look like a potfile")
                        print(f"Offending line: {line}")
                        return False
                    if checked_lines > 5:
                        break
        except Exception as msg:
            print(f"Exception when trying to open the {self.name} pot file: {filename} : {msg}")
            return -1

    def load_potfile(self, filename, hash_list):
        """
        Loads in newly cracked hashes into hash_list

        Inputs:
            filename: (String) The potfile to load

            hash_list: (HashList) The list of hashes to update

        Returns:
            new_cracks: (Int) The number of newly cracked passwords

            -1: If a problem occured
        """
        # Check that it looks like a potfile first
        if not self.is_potfile(filename):
            print(f"Can not load potfile {filename} since it did not look like a potfile")
            return -1

        num_cracked = 0
        try:
            with open(filename) as potfile:
                for line in potfile:
                    hash, divider, plain = line.partition(":")
                    
                    # I need to index the hash list for quicker lookups, so this is totally inefficient
                    for cur_hash in hash_list.hashes:
                        if getattr(cur_hash, self.hash_type) == hash:
                            if not cur_hash.plaintext:
                                num_cracked += 1
                                cur_hash.plaintext = plain
                                hash_list.hash_types[cur_hash.type]['cracked'] +=1
                            continue

        except Exception as msg:
            print(f"Exception when trying to parse JtR pot file: {msg}")
            return -1
    
        return num_cracked

    def update_pot(self, filename, hash_list):
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
        num_cracked = 0

        try:
            with open(self.main_pot_file) as potfile:
                for line in potfile:
                    hash, divider, plain = line.partition(":")
                    
                    # I need to index the hash list for quicker lookups, so this is totally inefficient
                    for cur_hash in hash_list.hashes:
                        if getattr(cur_hash, self.hash_type) == hash:
                            if not cur_hash.plaintext:
                                num_cracked += 1
                                cur_hash.plaintext = plain
                                hash_list.hash_types[cur_hash.type]['cracked'] +=1
                            continue

        except Exception as msg:
            print(f"Exception when trying to parse {self.name} pot file: {msg}")
            return -1
    
        return num_cracked  