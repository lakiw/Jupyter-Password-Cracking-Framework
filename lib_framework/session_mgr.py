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

    def pie_graph_metadata(self, meta_field, has_plaintext=False):
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

        graph_info = {
            'labels':[],
            'values':[]
        }

        for key, value in data.items():
            graph_info['labels'].append(key)
            graph_info['values'].append(value)

        fig, ax = plt.subplots()
        ax.pie(graph_info['values'], labels=graph_info['labels'], autopct='%1.1f%%');

        return