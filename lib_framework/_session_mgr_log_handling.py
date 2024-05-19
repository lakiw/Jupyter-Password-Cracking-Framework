"""
Python Mixin extension to the SessionMgr class to hold functions related to parsing
password cracking tool logs

Since this is a Mixin instance, it is not stand alone code.
I wanted to reduce the size of the main SessionMgr file so I'm seperating out the
log manipulation, analysis, and viewing functionality into this file

Dev Note: If you want to add your own views and analysis of password cracking session files
feel free to put them into this file as well vs. the main SessionMgr class.
"""


import os


class Mixin:

    def read_all_logs(self):
        """
        Reads in all of the password cracking log files (JtR and HashCat) and save the Sessions
        and Strikes.

        This is a top level function to hide the default folder from the user so they don't need
        to remember to pass it in. I'm also putting most of the functionality in self.read_logs_from_folder()
        since I want to be able to easily manually call the lower level function with a specific folder.

        Inputs:
            None

        Outputs:
            True: Everything compleated sucessfully

            False: There was a problem
        """
        jtr_success = False
        if self.jtr.log_directory:
            jtr_success = self.read_logs_from_folder(self.jtr.log_directory, cracker_name="jtr")

        hc_success = False
        if self.hc.log_directory:
            hc_success = self.read_logs_from_folder(self.jtr.log_directory, cracker_name="hc")

        if jtr_success or hc_success:
            return True
        
        return False
        
    def read_logs_from_folder(self, folder_name, cracker_name="all"):
        """
        Reads in all of the password cracking log files (JtR and HashCat) and save the Sessions
        and Strikes.

        This is a top level function to hide the default folder from the user so they don't need
        to remember to pass it in.

        Inputs:
            folder_name: The folder to read the logs in from

        Outputs:
            True: Everything compleated sucessfully

            False: There was a problem
        """

        # If at least one log was successfully parsed
        log_success = False

        # Parse the JtR log files
        if cracker_name in ['all', 'jtr']:
            for file_name in os.listdir(folder_name):
                if file_name.endswith(".log"):
                    full_file_name = os.path.join(folder_name, file_name)
                    if self.jtr.is_logfile(filename=full_file_name):
                        result = self.jtr.read_logfile(filename=full_file_name, session_list=self.session_list, strike_list=self.strike_list, hash_list=self.hash_list)
                        if result:
                            log_success = True

        # Parse the HC log files
        if cracker_name in ['all', 'hc']:
            for file_name in os.listdir(folder_name):
                if file_name.endswith(".log"):
                    full_file_name = os.path.join(folder_name, file_name)
                    if self.hc.is_logfile(filename=full_file_name):
                        result = self.hc.read_logfile(filename=full_file_name, session_list=self.session_list, strike_list=self.strike_list, hash_list=self.hash_list)
                        if result:
                            log_success = True

        return log_success
    
    def print_log_sessions(self):
        """
        Prints a human readable info about the top level sessions that have been run based on logs. Primarally focuses on JtR
        sessions as Hashcat logs don't contain information about sessions that have been run that did not crack passwords

        Inputs:
            None

        Returns:
            None
        """
        
        for hash_type in self.session_list.hash_type_lookup:
            print(f"Logs for Hash Type: {hash_type}")
            for index in self.session_list.hash_type_lookup[hash_type]:
                print(f"    Session ID: {index}")
                print(f"        Tool: {self.session_list.sessions[index].tool}")
                print(f"        Num Cracked Hashes: {self.session_list.sessions[index].num_cracked_hashes}")
                if self.session_list.sessions[index].options['num_loaded']:
                    print(f"        Loaded: {self.session_list.sessions[index].options['num_loaded']}")
                print(f"        Compleated: {self.session_list.sessions[index].compleated}")
                if self.session_list.sessions[index].options['total_time']:
                    print(f"        Run Time (seconds): {self.session_list.sessions[index].options['total_time']}")
                print(f"        Cracking Mode: {self.session_list.sessions[index].mode}")
               
                # Print out useful info about sessions
                if 'wordlist' in self.session_list.sessions[index].options:
                    print(f"            Wordlist: {self.session_list.sessions[index].options['wordlist']}")
                if 'ruleset' in self.session_list.sessions[index].options:
                    print(f"            Ruleset: {self.session_list.sessions[index].options['ruleset']}")
                if 'num_rules' in self.session_list.sessions[index].options:
                    print(f"            Num Rules: {self.session_list.sessions[index].options['num_rules']}")
                if 'incremental' in self.session_list.sessions[index].options:
                    print(f"            Incremental Attack: {self.session_list.sessions[index].options['incremental']}")

                # Single cracking mode specific outputs
                if 'incremental_started' in self.session_list.sessions[index].options:
                    print(f"            Incremental Attack Started (seconds): {self.session_list.sessions[index].options['incremental_started']}")
                elif self.session_list.sessions[index].mode == 'single':
                    print(f"            Wordlist Only Attack")

                # Prince crackng mode specific outputs
                if 'min_length' in self.session_list.sessions[index].options:
                    print(f"            Minimum Guess Length: {self.session_list.sessions[index].options['min_length']}")
                if 'min_length' in self.session_list.sessions[index].options:
                    print(f"            Maximum Guess Length: {self.session_list.sessions[index].options['max_length']}")
                if 'min_elements' in self.session_list.sessions[index].options:
                    print(f"            Minimum PRINCE Elements: {self.session_list.sessions[index].options['min_elements']}")
                if 'max_elements' in self.session_list.sessions[index].options:
                    print(f"            Maximum PRINCE Elements: {self.session_list.sessions[index].options['max_elements']}")

                # Mask cracking mode specific outputs
                if 'mask' in self.session_list.sessions[index].options:
                    print(f"            Mask Attack: {self.session_list.sessions[index].options['mask']}")
