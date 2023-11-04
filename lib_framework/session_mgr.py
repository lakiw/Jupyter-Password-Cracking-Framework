"""
Wrapper functionality for everything required to initialize
a cracking session.

Responsible for loading configs, hashes, and configuring
interfaces. Also stores them for easy access by other
functions in the Jupyter Notebook
"""


# Data analysis and visualization imports
import matplotlib.pyplot as plt

# Local imports
from .config_mgmt import load_config
from .jtr_mgr import JTRMgr
from .hashcat_mgr import HashcatMgr
from .challenge_specific_functions import load_challenge_files
from .hash import HashList
from .target import TargetList


class SessionMgr:
    """
    Making it easy to reference hashes, configs,
    and interfaces from the Jupyter Notebook
    """

    def __init__(self, config_file, load_challenge = True):
        """
        Sets up everything and loads the hashes
        """

        # Load the config
        self.config = load_config(config_file)
        if not self.config:
            print(f"Error opening the config file.")
            raise Exception
        
        # Initialize the password cracking managers
        if "jtr_config" in self.config:
            self.jtr = JTRMgr(self.config['jtr_config'])
        else:
            self.jtr = JTRMgr({})
        
        if "hashcat_config" in self.config:
            self.hc = HashcatMgr(self.config['hashcat_config'])
        else:
            self.hc = HashcatMgr({})

        # Load the hashes
        self.hash_list = HashList()
        self.target_list = TargetList()
        if load_challenge:
            if "challenge_files" in self.config and self.config['challenge_files']:
                for name, details in self.config['challenge_files'].items():
                    if 'format' not in details:
                        print(f"Error: You need to speficy a format for the Challenge file: {name}")
                        continue
                    if not load_challenge_files(details, self.hash_list, self.target_list):
                        print(f"Error: Could not load chellenge file {name}")
                        raise Exception 
            else:
                print(f"No challenge files specified in {config_file} so no hashes were loaded")

        # Init the scores
        if "score_info" in self.config:
            self.hash_list.init_scores(self.config['score_info'])

    def load_main_pots(self, verbose=True, update_only=True):
        """
        Responsible for going through the main JtR and Hashcat pots and updating cracked passwords
        
        Inputs:
            verbose: (Bool) If true, will print out more statistics about the
            new hashes that were loaded

            update_only: (Bool) If true, will not load any hashes that are not already in TargetList.
            This is to keep results from other cracking sessions from muddying the current cracking session
            analysis being done.
        """
        if self.jtr:
            new_cracks = self.jtr.load_potfile(self.jtr.main_pot_file, self.hash_list, update_only=update_only) 
            if new_cracks == -1:
                print(f"Error loading hashes from the main John the Ripper pot file {self.jtr.main_pot_file}")
            elif verbose:
                print(f"Number of new JtR cracked passwords: {new_cracks}")

        if self.hc:
            new_cracks = self.hc.load_potfile(self.hc.main_pot_file, self.hash_list, update_only=update_only) 
            if new_cracks == -1:
                print(f"Error loading hashes from the main Hashcat pot file {self.hc.main_pot_file}")
            elif verbose:
                print(f"Number of new HC cracked passwords: {new_cracks}")

    def update_main_pots(self, verbose=True):
        """
        Responsible for updating the main pot files with any new plaintexts that
        they are missing. This is helpful to sync between JtR and Hashcat
        cracking sessions

        Inputs:
            verbose: (Bool) If true, will print out more statistics about the
            new hashes that were added to each pot file
        """
        if self.jtr:
            new_cracks = self.jtr.update_potfile(self.jtr.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error updating hashes in the main John the Ripper pot file {self.jtr.main_pot_file}")
            elif verbose:
                print(f"Number of new plains added to the JtR pot file: {new_cracks}")

        if self.hc:
            new_cracks = self.hc.update_potfile(self.hc.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error updating hashes in the main Hashcat pot file {self.hc.main_pot_file}")
            elif verbose:
                print(f"Number of new plains added to the Hashcat pot file: {new_cracks}") 

    def print_status(self):
        """
        Prints uncracked/cracked information broken up by
        hash algorithm
        """
        print("Algorithm      :Total     :Cracked   :Remaining :Percentage")
        for type, info in self.hash_list.type_info.items():
            # Don't print out modes/types that don't have any hashes associated with them
            if info['total'] != 0:
                print(f"{type:<15}:{info['total']:<10}:{info['cracked']:<10}:{info['total']-info['cracked']:<10}:{info['cracked']/info['total']:.0%}")

    def print_score(self):
        """
        Prints the current score as defined by the config file
        Aka it looks through all the cracked hashes and assigns them points
        based on how much they were defined to be worth.

        This is used for password cracking competitions.

        If a score wasn't defined in the config file it prints a warning message stating that
        """

        # First perform a quick pass to see if any scores were defined
        score_defined = False
        for type, values in self.hash_list.type_info.items():
            if values['score']:
                score_defined = True
                break
        
        if not score_defined:
            print("No scores defined for the hash types. You can define this in the config file")
            print("For example:")
            print("  score_info:")
            print("    bcrypt: 16777215")
            return

        # Figure out the score and print out the current value for each hash type
        total_score = 0
        # Total possible points if all hashes were cracked
        max_total_score = 0
        print(f"{'Hash Type:':<15}{'Value Per Crack:':<20}{'Points Earned:':<20}{'Total Possible Points:'}")
        for type, type_hl in self.hash_list.type_list.items():
            # If a score wasn't defined but there were hashes
            if not self.hash_list.type_info[type]['score'] and type_hl:
                print(f"{type:<15}{'No Score Defined':<20}{0:<20}{0}")
            
            # Else if hashes exist
            elif type_hl:
                # Score earned for this hash type
                hash_score = 0
                # Total possible points if all hashes of this type were cracked
                max_hash_score = 0
                for hash_index in type_hl:
                    max_hash_score += self.hash_list.type_info[type]['score']
                    if self.hash_list.hashes[hash_index].plaintext:
                        hash_score += self.hash_list.type_info[type]['score']
                print(f"{type:<15}{self.hash_list.type_info[type]['score']:<20}{hash_score:<20}{max_hash_score}")

                total_score += hash_score
                max_total_score += max_hash_score

        print()
        print(f"Total Score: {total_score}")
        print(f"Maximum Possible Score: {max_total_score}")
                

    
    def print_metadata_categories(self):
        """
        Prints the metadata categories available to search/graph on
        """

        print(f"{'Metadata Type':<20}:Unique Values")
        for key, items in self.target_list.meta_lookup.items():
            print(f"{key:<20}:{len(items.keys())}")

    def print_metadata_items(self, meta_field):
        """
        Prints out every unique metadata item for a particular key.
        Will also print out counts for the item and number cracked

        Inputs:
            meta_field: (Str) The metadata key to search on
        """
        data = {}

        # Check to see the key is in the target metadata
        if meta_field not in self.target_list.meta_lookup:
            print(f"Error: The field {meta_field} was not in the target list metadata. No data to print out")
            return

        print(f"{meta_field:<{25}}:Number of Hashes :Cracked")
        # Loop through the instances of the metadata key
        for meta_value in self.target_list.meta_lookup[meta_field].keys():
            stats = self.target_list.get_stats_metadata(meta_field, meta_value, self.hash_list)
            print(f"{meta_value:<{25}}:{stats['num_hashes']:<17}:{stats['num_cracked']}")

    def print_single_plaintext_by_hash_index(self, hash_index, meta_fields=[], col_width = []):
        """
        Prints a single plaintext for a hash + associated metadata fields

        May print multiple targets for the same plaintext if they share hashes

        Inputs:
            hash_index: (Int) An index for a hash to display the plaintext for

            meta_fields: (List) A list of all the metavariable fields to print out
            along with the cracked password

            col_width: (List) How long each metavariable column should be. Needs to be a 1 to 1 mapping
            with meta_fields. Just makes things easier to read
        """
        # A hash may not have a target associated with it. In that case, print N/A for all the categories
        if hash_index not in self.target_list.hash_lookup:
            for spacer_len in col_width:
                print(f"{'<N/A>':<{spacer_len}}",end='')
            print(f"{self.hash_list.hashes[hash_index].plaintext}")
            return

        # A single hash may be associated with multiple targets
        for target_index in self.target_list.hash_lookup[hash_index]:
            for list_pos, field in enumerate(meta_fields):
                # The field may not exist so it may throw a KeyError
                try:
                    print(f"{self.target_list.targets[target_index].metadata[field]:<{col_width[list_pos]}}", end="")
                except KeyError:
                    print(f"{'<N/A>':<{col_width[list_pos]}}",end='')
            print(f"{self.hash_list.hashes[hash_index].plaintext}")
        
    def print_all_plaintext(self, sort_field=None, meta_fields=[], col_width = []):
        """
        Prints all the cracked passwords for manual evaluation
        
        WARNING: If you've cracked a lot of passwords (which is a good thing!) this
        can take up a lot of screen real estate.

        Inputs:
            sort_field: (String) The metavalue field to sort the cracked plaintext
            values by. If None, it will sort by hash type instead

            meta_fields: (List) A list of all the metavariable fields to print out
            along with the cracked passwords

            col_width: (List) How long each metavariable column should be. Needs to be a 1 to 1 mapping
            with meta_fields. Just makes things easier to read
        """

        # First do some quick sanity checks to make sure the metadata fields exists
        if sort_field and sort_field not in self.target_list.meta_lookup:
            print(f"Error: The sort_field {sort_field} was not in the target list metadata. Canceling printing hashes")
            return

        for field in meta_fields:
            if field not in self.target_list.meta_lookup:
                print(f"Error: The meta_field {field} was not in the target list metadata. Canceling printing hashes")
                return

        # Default width of metadata fields if they were not specified
        default_width = 25

        # Fill out the col_width with the default width if they are not specified
        while len(col_width) < len(meta_fields):
            col_width.append(default_width)

        # Sort by hash type
        if not sort_field:
            for type, hash_index_list in self.hash_list.type_list.items():
                # Used to say if any hashes were cracked for the type or not
                cracks_exist = False
                
                # No hashes
                if not hash_index_list:
                    continue

                # Print the header
                print(f"HASH TYPE: {type} ----------------------------------------------------------")
                for list_pos, field in enumerate(meta_fields):
                    print(f"{field:<{col_width[list_pos]}}", end="") 
                print("Plaintext")
                
                # Print the actual values
                for hash_index in hash_index_list:
                    if self.hash_list.hashes[hash_index].plaintext:
                        cracks_exist = True
                        self.print_single_plaintext_by_hash_index(hash_index, meta_fields, col_width)
                
                if not cracks_exist:
                    print(f"<No Cracked Hashes Exist For This Category>")

        # Sort by metadata field
        else:
            for sort_value in self.target_list.meta_lookup[sort_field]:
                # Used to say if any hashes were cracked for the type or not
                cracks_exist = False
                
                # Print the header
                print(f"Sort Field: {sort_field}: Value: {sort_value} ----------------------------------------------------------")
                for list_pos, field in enumerate(meta_fields):
                    print(f"{field:<{col_width[list_pos]}}", end="") 
                print("Plaintext")

                for target_index in self.target_list.meta_lookup[sort_field][sort_value]:
                    for hash_index in self.target_list.targets[target_index].hashes:
                        if self.hash_list.hashes[hash_index].plaintext:
                            cracks_exist = True
                            self.print_single_plaintext_by_hash_index(hash_index, meta_fields, col_width)

                if not cracks_exist:
                    print(f"<No Cracked Hashes Exist For This Category>")
        return

    def pie_graph_metadata(self, meta_field, has_plaintext=False, top_x=None, plot_size=5):
        """
        Creates a pie graph based on hash metadata

        Inputs:
            meta_field: (String) The name of the metadata field. Capitalization matters.

            has_plaintext: (Bool) If true, only include hashes that have been cracked
        """
        if meta_field not in self.target_list.meta_lookup:
            print(f"Error: The meta_field {meta_field} was not in the target list metadata. Canceling making the pie chart")
            return

        data = {}
        # Create the statistics
        for meta_value in self.target_list.meta_lookup[meta_field].keys():
            stats = self.target_list.get_stats_metadata(meta_field, meta_value, self.hash_list)
            if has_plaintext:
                # Don't create categories for targets that don't have cracks
                if stats['num_cracked'] == 0:
                    continue
                data[meta_value] = stats['num_cracked']
            else:
                # Don't create categories for targets that don't have hashes
                if stats['num_hashes'] == 0:
                    continue
                data[meta_value] = stats['num_hashes']

        # Sort the results
        sorted_data = sorted(data, key=data.get, reverse=True)

        graph_info = {
            'labels':[],
            'values':[]
        }

        num_items = 1
        the_rest = 0
        for item in sorted_data:
            if not top_x or num_items <= top_x:
                graph_info['labels'].append(item)
                graph_info['values'].append(data[item])
            else:
                the_rest += data[item]

            num_items += 1

        if the_rest != 0:
            graph_info['labels'].append("The Rest")
            graph_info['values'].append(the_rest)

        if not graph_info['labels']:
            print("Sorry, there was no data to graph")
            if has_plaintext:
                print("Maybe crack a few more passwords?....")
            return
        
        plt.rcParams['figure.figsize'] = [plot_size, plot_size]
        fig, ax = plt.subplots()
        ax.pie(graph_info['values'], labels=graph_info['labels'], autopct='%1.1f%%');

        return

    def create_left_list(self, is_jtr=True, file_name=None, hash_type=None, filter=None):
        """
        Creates a hash file of uncracked hashes

        Inputs:
            is_jtr: (Bool) If True, this should format the left list for John the Ripper

            file_name: (String) If it is not None, write the left list to this filename. If
            it is None, write the results to stdout instead.

            hash_type: (String) If not none, only write hashes of this type to the left list.
            If None, then it will write all uncracked hashes to this list regardless of type

            filter: (Dict) All key/value pairs must match metadata for uncracked hashes to
            be written to the left list. If None the filter is ignored. If a value is None, then
            it will write all hashes that have a metadata with the particular key set.
        """

        # Sanity check on filter values to make sure they are correct
        if hash_type and hash_type not in self.hash_list.type_info:
            print(f"Error: hash_type of {hash_type} is not a type that has been loaded into this framework")
            return
        
        if filter:
            for key, value in filter.items():
                if key not in self.target_list.meta_lookup:
                    print(f"Error: filter/metadata with a key of of {key} has not been entered into the target/metadata datastructures")
                    return
                if value and value not in self.target_list.meta_lookup[key]:
                    print(f"Error: filter/metadata with a key of of {key} and value of {value} has not been entered into the target/metadata datastructures")
                    return
        
        # If not printing to stdout, open the file 
        if file_name:
            try:
                file = open(file_name, mode='w')
            except Exception as msg:
                print(f"Exception writing to {file_name}: {msg}")
                return
        else: 
            file = None

        # There are multiple layers of optimization that can be made here based on the filters
        # and the hash types so that only a small subset of hashes need to be searched/checked
        # to generate the left list. I'm concerned about the code complexity though so for
        # this current implimentation I'm just going to loop through all hashes and then
        # apply filters to them to see if they should be included in the left list
        for hash_id, hash in self.hash_list.hashes.items():
            # First filter, if it has a plaintext, don't include it in the left list
            if hash.plaintext:
                continue

            # Next filter based on hash type if it was specified
            if hash_type and self.hash_list.type_lookup[hash_id] != hash_type:
                continue

            # Next filter based on filters/metadata
            if filter:
                # Assume it matches and break when it doesn't
                match_filter = True
                
                # There can be multiple filters, so go through each one
                for filter_key, filter_value in filter.items():

                    # Need to find an instance where this hash maches something matching this filter
                    found = False

                    # Go through all the targets that match this filter
                    for cur_value, target_ids in self.target_list.meta_lookup[filter_key].items():
                        # If a value has been specified, skip not filter_value entries
                        if filter_value:
                            if cur_value != filter_value:
                                continue
                    
                        for single_target in target_ids:
                            if hash_id in self.target_list.targets[single_target].hashes:
                                found = True
                                break

                    if not found:
                        match_filter = False
                        break
                
                if not match_filter:
                    continue

            # Add this hash to the left list
            # Format the hash for the target password cracking program
            if is_jtr:
                out_hash = self.jtr.format_hash(hash.hash, self.hash_list.type_lookup[hash_id])
            else:
                out_hash = self.hc.format_hash(hash.hash, self.hash_list.type_lookup[hash_id])
            
            if file:
                file.write(f"{out_hash}\n")
            else:
                print(f"{out_hash}")

        # Close the file
        if file:
            file.close()

        return