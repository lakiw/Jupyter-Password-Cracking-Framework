"""
A class to represent inidivual hashes and a class to
hold all of the hashes.

I figure this might be easier to manage for others than
having random dictionaries to figure out. Also this
will allow me to swap out the underlying infrastructure if
I later decided to add a database to store them.

The hash class itself is super basic. It holds the hash,
and the plaintext. This is to make it easier
to support more serious password datasets that may have
millions of entries and database storage.

To put it another way, I always add more values to Hash like
classes and I always regret doing that. Trying to learn from
past mistakes
"""


class Hash:
    """
    Keeps track of hashes and plaintexts
    """

    def __init__(self, hash, plaintext = None):
        """
        Inputs:
            hash: (String) The raw hash

            type: (String) A definition of the hash algorithm

            plaintext: (String) The plaintext value (if known)
        """
        self.hash = hash
        self.plaintext = plaintext
    
    def __lt__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.hash) < (obj.hash))
  
    def __gt__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.hash) > (obj.hash))
  
    def __le__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.hash) <= (obj.hash))
  
    def __ge__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return ((self.hash) >= (obj.hash))
  
    def __eq__(self, obj):
        """
        Overloading comparison operators and making
        the orig_hash be the main key
        """
        return (self.hash == obj.hash)
  
    def __repr__(self):
        """
        Making this easier to read
        """
        if self.plaintext:
            return f"{self.hash}:{self.plaintext}"
        return f"{self.hash}:"
    

class HashList:
    """
    Keeps track of all the hashes
    """

    def __init__(self):
        """
        Pretty boring, just initializes all the datastructures
        """

        # Holds all the hashes
        # The key is the index that other related datastructures will
        # reference (vs. referencing the raw hashes)
        self.hashes = {}

        # Keeps track of the next index number to assign for the hashes
        self.next_index = 0

        # Key = hash, value = Index into hashes.
        # Used for quick lookups
        self.hash_lookup = {}

        # Used to quickly look up submission status for different hashes
        # 0 = not submitted; 1 submitted; 2 = acknowledged
        self.sub_lookup = {}

        # Key = index, value = hash type
        # Used to associate a cracking mode with a hash
        self.type_lookup = {}

        # Key = type, value = [list of hash indexes]
        self.type_list = {}

        # Information about the hash types
        self.type_info = {}

        # value to assign unknown hash types
        self.unknown_type = "unknown"
        self.add_type(self.unknown_type, jtr_mode=None, hc_mode=None, cost=None)

    def add(self, hash, type=None, plaintext=None):
        """
        Adds a hash to the list.

        If the hash exists already but the existing type or the plaintext
        is not set, and new values are passed in, update them

        Inputs:
            hash: (STR) The string representation of the hash

            type: (STR) The hash algorithm used

            plaintext: (STR) The cracked password

        Returns:
            new_crack: (INT) 0 if the plaintext isn't new.
            1 if the plaintext is new
        """
        # Basically just a frontend to the private _add_update function
        return self._add_update(hash, type=type, plaintext=plaintext, update_only=False)

    def update(self, hash, type=None, plaintext=None):
        """
        Updates a hash. Will not add it if it is new.

        Inputs:
            hash: (STR) The string representation of the hash

            type: (STR) The hash algorithm used

            plaintext: (STR) The cracked password

        Returns:
            new_crack: (INT) 0 if the plaintext isn't new.
            1 if the plaintext is new
        """
        # Basically just a frontend to the private _add_update function
        return self._add_update(hash, type=type, plaintext=plaintext, update_only=True)

    def _add_update(self, hash, type=None, plaintext=None, update_only=False):
        """
        Adds a hash to the list if update_only is False. Otherwise will only update an
        existing hash. Making this a private function since it's basically the same
        code for adding/updating.

        In all cases, if the hash exists already but the existing type or the plaintext
        is not set, and new values are passed in, update them

        Inputs:
            hash: (STR) The string representation of the hash

            type: (STR) The hash algorithm used

            plaintext: (STR) The cracked password

            update_only: (BOOL) If true will not add a new hash to HashList

        Returns:
            new_crack: (INT) 0 if the plaintext isn't new.
            1 if the plaintext is new
        """
        new_crack = 0

        # Check type is supported and if not, add it
        if type and type not in self.type_info:
            print(f"Warning, adding a hash type that hasn't been formally entered yet. Type: {type}")
            self.add_type(type, jtr_mode=None, hc_mode=None, cost=None)
        elif not type:
            type = self.unknown_type

        # Check if the hash has been added already.
        if hash in self.hash_lookup:
            index = self.hash_lookup[hash]

            # Update type if it was not set before or was incorrectly set
            if type != self.unknown_type and self.type_lookup[index] != type:
                prev_type = self.type_lookup[index]

                self.type_list[prev_type].remove(index)
                self.type_list[type].append(index)
                self.type_lookup[index] = type

                # Update counts for the types
                self.type_info[prev_type]['total'] -= 1
                self.type_info[type]['total'] += 1
                if self.hashes[index].plaintext:
                    self.type_info[prev_type]['cracked'] -= 1
                    self.type_info[type]['cracked'] += 1
            else:
                type = self.type_lookup[index]

            # Update the plaintext. Aka if you are loading a pot and have
            # now cracked a password
            if not self.hashes[index].plaintext and plaintext:
                self.hashes[index].plaintext = plaintext
                
                # Update the count info
                self.type_info[type]['cracked'] += 1
                new_crack = 1
        elif not update_only:
            # Add the hash
            self.hash_lookup[hash] = self.next_index
            self.hashes[self.next_index] = Hash(hash, plaintext)
            self.type_lookup[self.next_index] = type
            self.type_list[type].append(self.next_index)

            # Update the submission info
            self.sub_lookup[self.next_index] = 0

            self.next_index += 1

            # Update the statistics info
            self.type_info[type]['total'] += 1
            if plaintext:
                self.type_info[type]['cracked'] += 1
                new_crack = 1
                
        return new_crack

    def add_type(self, type, jtr_mode, hc_mode, cost):
        """
        Adds a hash type/algorithm to the list.
        """
        if type not in self.type_info:
            self.type_info[type] = {
                'jtr_mode':jtr_mode,
                'hc_mode':hc_mode,
                'cost':cost,
                'total':0,
                'cracked':0,
                'score':0
            }
            self.type_list[type] = []

        # Update info if not set
        else:
            if not self.type_info[type]['jtr_mode']:
                self.type_info[type]['jtr_mode'] = jtr_mode
            if not self.type_info[type]['hc_mode']:
                self.type_info[type]['hc_mode'] = hc_mode
            if not self.type_info[type]['cost']:
                self.type_info[type]['cost'] = cost

    def init_scores(self, score_info):
        """
        Initializes score info for the hash types
        """
        for type, value in score_info.items():
            if type not in self.type_info:
                print(f"INFO: No hashes of type: {type} found in current challenge files. Each hash is worth: {value}")
                print(f"Adding the type to the hash list datastructures, but jtr mode and hc mode still need to be added to use some functionality")
                self.add_type(type, jtr_mode=None, hc_mode=None, cost=None)
            else:
                self.type_info[type]['score'] = value