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
        self.jtr = None
        if "jtr_config" in self.config:
            self.jtr = JTRMgr(self.config['jtr_config'])
        
        self.hc = None
        if "hashcat_config" in self.config:
            self.hc = HashcatMgr(self.config['hashcat_config'])

        # Load the hashes
        self.hash_list = HashList()
        if load_challenge:
            if "challenge_files" in self.config and self.config['challenge_files']:
                for name, details in self.config['challenge_files'].items():
                    if 'format' not in details:
                        print(f"Error: You need to speficy a format for the Challenge file: {name}")
                        continue
                    if not load_challenge_files(details, self.hash_list):
                        print(f"Error: Could not load chellenge file {name}") 
            else:
                print(f"No challenge files specified in {config_file} so no hashes were loaded")

        # Init the scores
        if "score_info" in self.config:
            self.hash_list.init_scores(self.config['score_info'])

    def load_main_pots(self, verbose=True):
        """
        Responsible for going through the main JtR and Hashcat pots and updating cracked passwords
        
        Inputs:
            verbose: (Bool) If true, will print out more statistics about the
            new hashes that were loaded
        """
        if self.jtr:
            new_cracks = self.jtr.load_potfile(self.jtr.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error loading hashes from the main John the Ripper pot file {self.jtr.main_pot_file}")
            elif verbose:
                print(f"Number of new JtR cracked passwords: {new_cracks}")

        if self.hc:
            new_cracks = self.hc.load_potfile(self.hc.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error loading hashes from the main Hashcat pot file {self.jtr.main_pot_file}")
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
            new_cracks = self.jtr.update_pot(self.jtr.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error updating hashes in the main John the Ripper pot file {self.jtr.main_pot_file}")
            elif verbose:
                print(f"Number of new plains added to the JtR pot file: {new_cracks}")

        if self.hc:
            new_cracks = self.hc.update_pot(self.hc.main_pot_file, self.hash_list) 
            if new_cracks == -1:
                print(f"Error updating hashes in the main Hashcat pot file {self.jtr.main_pot_file}")
            elif verbose:
                print(f"Number of new plains added to the Hashcat pot file: {new_cracks}") 

    def print_status(self):
        """
        Prints uncracked/cracked information broken up by
        hash algorithm
        """
        print("Algorithm     :Total      :Cracked   :Remaining :Percentage")
        for type, info in self.hash_list.hash_types.items():
            print(f"{type:<15}:{info['total']:<10}:{info['cracked']:<10}:{info['total']-info['cracked']:<10}:{info['cracked']/info['total']:.0%}")

    def print_metadata_categories(self):
        """
        Prints the metadata categories available to search/graph on
        """

        # Rather than store this in ingest (which I probably should do)
        # I'm going to loop through everything and create a lookup dictionary
        metadata_map = {}
        for hash in self.hash_list.hashes:
            for target in hash.targets:
                for type in target['metadata']:
                    if type in metadata_map:
                        metadata_map[type] += 1
                    else:
                        metadata_map[type] = 1

        print(f"{'Metadata Type':<20}:Count")
        for key, value in metadata_map.items():
            print(f"{key:<20}:{value}")


    def print_metadata_items(self, meta_field):
        """
        Prints out every unique metadata item for a particular key.
        Will also print out counts for the item and percent cracked
        """
        data = {}

        # Used to make the printouts pretty
        longest_name = len(meta_field)

        # Create the statistics
        for hash in self.hash_list.hashes:
            for target in hash.targets:
                if meta_field in target['metadata']:
                    if target['metadata'][meta_field] in data:
                        data[target['metadata'][meta_field]]['count'] +=1
                    else:
                        data[target['metadata'][meta_field]] = {'count':1,'plaintext':0}
                        if len(target['metadata'][meta_field]) > longest_name:
                            longest_name = len(target['metadata'][meta_field])
                    if hash.plaintext:
                        data[target['metadata'][meta_field]]['plaintext'] +=1

        print(f"{meta_field:<{longest_name}}:Count :Cracked")
        for item in data:
            print(f"{item:<{longest_name}}:{data[item]['count']:<6}:{data[item]['plaintext']}")

    def print_all_plaintext(self, sort_field=None, meta_fields=[], col_width = []):
        """
        Prints all the cracked passwords for manual evaluation
        
        WARNING: If you've cracked a lot of passwords (which is a good thing!) this
        can take up a lot of screen realestate.

        Inputs:
            sort_field: (String) The metavalue field to sort the cracked plaintext
            values by

            meta_fields: (List) A list of all the metavariable fields to print out
            along with the cracked passwords

            col_width: (List) How long each metavariable column should be. Needs to be a 1 to 1 mapping
            with meta_fields. Just makes things easier to read
        """
        return

    def pie_graph_metadata(self, meta_field, has_plaintext=False, top_x=None, plot_size=5):
        """
        Creates a pie graph based on hash metadata

        Inputs:
            meta_field: (String) The name of the metadata field. Capitalization matters.

            has_plaintext: (Bool) If true, only include hashes that have been cracked
        """
        data = {}
        # Create the statistics
        for hash in self.hash_list.hashes:
            if not has_plaintext or hash.plaintext:
                for target in hash.targets:
                    if meta_field in target['metadata']:
                        if target['metadata'][meta_field] in data:
                            data[target['metadata'][meta_field]] += 1
                        else:
                            data[target['metadata'][meta_field]] = 1

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

