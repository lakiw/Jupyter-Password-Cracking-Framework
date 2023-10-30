"""
Contains functionality for managing John the Ripper password cracker

Not indended to run full cracking sessions. Functionality
is more for syncing pot files, identifying cracked hashes,
and running simple loopback attacks.
"""


from.pw_cracker_mgr import PWCrackerMgr


class JTRMgr(PWCrackerMgr):
    """
    Base functionality for keeping track of JTR
    cracked passwords and running limited JTR functionality
    """

    def __init__(self, config):
        super().__init__(config)
        
        # Set cracker specific variables (default is JtR since I'm biased)
        self.pot_extension = ".pot"
        self.hash_type = "jtr_hash"
        self.name = "John the Ripper"

    def normalize_hash(self, hash):
        """
        Convert from a password cracker hash format to a "normalized" format 
        used by this analysis platform

        For example, remove the $dynamic_X$ prefix of JtR hashes. Those are
        super helpful but that info is kept in the type_lookup datastructure of
        HashList().

        Inputs:
            hash: (str) The password hash to normalize

        Returns:
            normalized_hash: (str) The normalized verion of the hash
        """
        # I'm trying to avoid importing re, so using split instead
        hash_parts = hash.split("$dynamic_", 1)

        # Not a dynamic mode, so return the hash
        if len(hash_parts) != 2:
            return hash
        
        # Trim the trailing $
        hash_parts = hash_parts[1].split("$", 1)
        if len(hash_parts) != 2:
            print(f"Malformed dynamic mode found in your jtr pot file: {hash}")
            return None

        return hash_parts[1]
    
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
        if type == "raw_md5" or type == "raw-md5":
            return f"$dynamic_0${hash}"
        elif type == "raw_sha1" or type == "raw-sha1":
            return f"$dynamic_26${hash}"

        return hash