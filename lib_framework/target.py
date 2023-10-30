"""
Holds information about a particular target

This includes metadata and hashes for that target
"""


class Target:
    """
    Keeps track of target specific information

    - There is no primary key since I don't know what metadata
    will appear for a target
    - A target may have multiple hashes associated with it
    """

    def __init__(self, metadata={}, hashes=[]):
        """
        Inputs:
            metadata: (Dictionary) A key/value set of all the metadata info
            such as username, company, email, etc

            hashes: (List) A list of all hashes associated with the target.
            These are indexes to the hashes, and not the raw hashes themselves
        """
        self.metadata = metadata
        self.hashes = hashes


class TargetList:
    """
    Keeps track of all the targets

    Creating this class to help abstract access to the underlying Target
    clas
    """

    def __init__(self):
        """
        Pretty boring, just initializes all the datastructures
        """

        # Holds all the Targets
        # The key is the index that other related datastructures will
        # reference (vs. referencing the raw targets)
        self.targets = {}

        # Keeps track of the next index number to assign for the targets
        self.next_index = 0

        # Repeats the Target datastructures for each of the metadata fields
        # Horrible waste of space, but provides quick lookups which seems
        # useful for password cracking competitions
        #
        # Each key of a metadata field will reference a dictionary of all the unique values which
        # point to a list of all the targets referenced
        # E.g. {'username':{'bob':[BOB_TARGET],'sue':[SUE_TARGET]}}
        self.meta_lookup = {}

        # Quick lookup for all the targets that have a particular hash id (aka not
        # the actual hash, but the index for that hash
        # E.g. {1:[0,3,5]} for hash id 1 is found in targets with id 0,3,5
        self.hash_lookup = {}

    def find(self, metadata={}, hashes=[]):
        """
        Checks to see if the submitted metadata + hashes is equal to or a subset of an existing target

        Inputs:
            metadata: (Dict) A listing of all the metadata associated with the target

            hashes: (List) A list of all the hash indexes associated with the target

        Returns:
            matched_targets: (List[Int]) A list of all the targets that match the submitted query

        """
        # First check the metadata associated with this target
        matched_targets = []
        for key, value in metadata.items():
            # A new item was found in the metadata so this Target is not in the list
            if key not in self.meta_lookup or value not in self.meta_lookup[key] or not self.meta_lookup[key][value]:
                return []
            else:
                # If this is the first run through
                if not matched_targets:
                    matched_targets = self.meta_lookup[key][value]
                # Find the union of previous targets and the targets with this metadata value
                else:
                    matched_targets = sorted(set(matched_targets).intersection(set(self.meta_lookup[key][value])))
                    # If the union is empty, this is a new target
                    if not matched_targets:
                        return []
                    
        # Next check the hashes associated with this target. Note, it is using the
        # matched_targets from the previous metadata lookup as well.
        for hash_index in hashes:
            # A new hash was found so this Target is not in the list
            if hash_index not in self.hash_lookup or not self.hash_lookup[hash_index]:
                return []
            else:
                # If this is the first run through
                if not matched_targets:
                    matched_targets = self.hash_lookup[hash_index]
                # Find the union of previous targets and the targets with this hash data
                else:
                    matched_targets = sorted(set(matched_targets).intersection(set(self.hash_lookup[hash_index])))
                    # If the union is empty, this is a new target
                    if not matched_targets:
                        return []
                    
        # Looks like a duplicate entry
        return matched_targets

    def add(self, metadata={}, hashes=[]):
        """
        Adds a target to the list.

        Currently DOES NOT do any duplicaiton detection

        Inputs:
            metadata: (Dict) A listing of all the metadata associated with the target

            hashes: (List) A list of all the hash indexes associated with the target

        Returns:
            new_target: (INT) 0 if the target isn't new.
            1 if the target is new
        """
        
        # Checks to see if the target is unique
        if self.find(metadata, hashes) != []:
            # Target(s) exists so don't add this new one
            return 0
        
        # Target is unique, so add it
        self.targets[self.next_index] = Target(metadata, hashes)

        # Update the lookup indexes
        for hash_index in hashes:
            if hash_index not in self.hash_lookup:
                self.hash_lookup[hash_index] = []
            # Don't need to check to see if the index is there since we're
            # creating a new index so it shouldn't have been used before
            self.hash_lookup[hash_index].append(self.next_index)

        for key, value in metadata.items():
            if key not in self.meta_lookup:
                self.meta_lookup[key] = {}
            if value not in self.meta_lookup[key]:
                self.meta_lookup[key][value] = []
            self.meta_lookup[key][value].append(self.next_index)
        
        self.next_index += 1
        return 1

    def get_stats_target(self, target_id, hash_list):
        """
        Returns some stats about the target as a dictionary

        Inputs:
            target_id: (int) The lookup id for the target

            hash_list: (HashList) Needed to look up the percentage of hashes that have been cracked

        Returns:
            stats: (dict) A dictionary of the stats. Currently it returns
            {
                'num_hashes':(int) Number of hashes for this target,
                'num_cracked':(int) Number of hashes that have been cracked for this target
            }
        """

        stats = {
            'num_hashes':0,
            'num_cracked':0,
        }

        # Raise an exception if the target doesn't exist
        if target_id not in self.targets:
            raise Exception

        for hash_id in self.targets[target_id].hashes:
            stats['num_hashes'] += 1
            if hash_list.hashes[hash_id].plaintext:
                stats['num_cracked'] += 1

        return stats

    def get_stats_metadata(self, meta_key, meta_value, hash_list):
        """
        Returns some stats about all the targets with a particular metadata key/value

        Note: If some targets share the same hashes, those hashes will be counted multiple times.
        Eventually I might want to add additional checking for that to make this more accurate.

        Inputs:
            meta_key: (Str) The top level key for the metadata item. E.g. "city"

            meta_value: (Str) The value for the metadata key to look up. E.g. "Boston"

            hash_list: (HashList) Needed to look up the percentage of hashes that have been cracked

        Returns:
            stats: (dict) A dictionary of the stats. Currently it returns
            {
                'num_hashes':(int) Number of hashes for this search,
                'num_cracked':(int) Number of hashes that have been cracked for this search
            }
        """

        stats = {
            'num_hashes':0,
            'num_cracked':0,
        }

        # Raise an exception if the metadata key doesn't exist
        if meta_key not in self.meta_lookup:
            print(f"Meta Key: {meta_key} not found in target metadata")
            raise Exception

        if meta_value not in self.meta_lookup[meta_key]:
            print(f"Meta Value: {meta_value} not found in target metadata for key:{meta_key}")
            raise Exception

        for target_id in self.meta_lookup[meta_key][meta_value]:
            item_stats = self.get_stats_target(target_id, hash_list)
            stats['num_hashes'] += item_stats['num_hashes']
            stats['num_cracked'] += item_stats['num_cracked']

        return stats