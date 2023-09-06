"""
A class to represent inidivual hashes and a class to
hold all of the hashes.

I figure this might be easier to manage for others than
having random dictionaries to figure out. Also this
will allow me to swap out the underlying infrastructure if
I later decided to add a database to store them.
"""


class Hash:
    """
    Keeps track of target specific hashes
    """

    def __init__(self, orig_hash, type, jtr_hash = None, hc_hash = None, submit_hash = None, source = None, username = None, metadata = {}, plaintext = None):
        """
        Inputs:
            orig_hash: (String) The format the hash was loaded up as

            type: (String) A definition of the hash algorithm

            jtr_hash: (String) The format to use for John the Ripper

            hc_hash: (String) The format to use for Hashcat

            submit_hash: (String) The format to submit these hases in (if this is a competition)

            source: (String) The source of this hash

            username: (String) The username for this hash

            metadata: (Dict) Other metadata associated with this hash

            plaintext: (String) The plaintext value (if known)
        """
        self.orig_hash = orig_hash
        self.type = type
        self.jtr_hash = jtr_hash
        self.hc_hash = hc_hash
        self.submit_hash = submit_hash
        self.plaintext = plaintext

        # The hash may be shared across multiple users
        # So create a list of targets
        single_target = {
            'source':source,
            'username':username,
            'metadata':metadata
        }
        self.targets = [single_target]
    
    def matches(self, input):
        """
        Sees if a hash matches this one

        Will be equal if the input matches any of the hashes for this hash
        Aka: the jtr_hash, the hc_hash, the orig_hash, or the submit_hash
        """
        if self.orig_hash == input:
            return True
        elif self.jtr_hash == input:
            return True
        elif self.hc_hash == input:
            return True
        elif self.submit_hash == input:
            return True
        return False
    
    def __lt__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.orig_hash) < (obj.orig_hash))
  
    def __gt__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.orig_hash) > (obj.orig_hash))
  
    def __le__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.b) <= (obj.b))
  
    def __ge__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.orig_hash) >= (obj.orig_hash))
  
    def __eq__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return (self.orig_hash == obj.orig_hash)
  
    def __repr__(self):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return str((self.orig_hash, self.orig_hash))
    

class HashList:
    """
    Keeps track of all the hashes
    """

    def __init__(self):
        """
        Pretty boring, just initializes all the datastructures
        """

        # Holds all the hashes
        self.hashes = []

        # Information about the hash types
        self.hash_types = {}

    def add(self, hash):
        """
        Adds a hash to the list.

        If the hash exists already, checks to see if the metadata
        is different to create a new target for the existing hash.
        """

        try: 
            index = self.hashes.index(hash)
            for target in hash.targets:
                if target not in self.hashes[index].targets:
                    self.hashes[index].targets.append(target)

        except ValueError:
            # Hash was not found, insert it
            self.hashes.append(hash)

        # Update the statistics info
        if hash.type not in self.hash_types:
            print("Error: You are adding a hash but the type hasn't been registered yet")
        else:
            self.hash_types[hash.type]['total'] += 1
            if hash.plaintext:
                self.hash_types[hash.type]['cracked'] += 1

    def add_type(self, type, jtr_mode, hc_mode, cost):
        """
        Adds a hash type/algorithm to the list.
        """
        if type not in self.hash_types:
            self.hash_types[type] = {
                'jtr_mode':jtr_mode,
                'hc_mode':hc_mode,
                'cost':cost,
                'total':0,
                'cracked':0,
                'score':0
            }

    def init_scores(self, score_info):
        """
        Initializes score info for the hash types
        """
        for type, value in score_info.items():
            if type not in self.hash_types:
                print(f"INFO: No hashes of type: {type} found in current challenge files. Each hash is worth: {value}")
            else:
                self.hash_types[type]['score'] = value