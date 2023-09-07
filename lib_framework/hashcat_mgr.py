"""
Contains functionality for managing a Hashcat password cracker

Not indended to run full cracking sessions. Functionality
is more for syncing pot files, identifying cracked hashes,
and running simple loopback attacks.
"""


from.pw_cracker_mgr import PWCrackerMgr


class HashcatMgr(PWCrackerMgr):
    """
    Base functionality for keeping track of Hashcat
    cracked passwords and running limited Hashcat functionality
    """

    def __init__(self, config):
        super().__init__(config)
        
        # Set cracker specific variables (default is JtR since I'm biased)
        self.pot_extension = ".potfile"
        self.hash_type = "hc_hash"
        self.name = "Hashcat"