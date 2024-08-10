"""
Responsible for keeping track of what cracked passwords have been submitted
and generating new submissions
"""


import datetime
import os


class SubmissionMgr:
    """
    Responsible for keeping track of what cracked passwords have been submitted
    and generating new submissions
    """

    def __init__(self, success_file, submission_file_prefix, hash_list):
        """
        Inputs:
            success_file: (String) The file that contains all the hashes sucessfully submitted
            This way we don't resubmit them accidently

            submission_file_prefix: (String) The filename prefix to save submission lists to.
            I'm doing this since I'm paranoid that this tool will crash/mess up, so that way
            I can see what I submitted and when. A number and .sav will be appended onto this
            prefix.

            hash_list: (HashList) The list of all hashes. Passing it in here to update
            them from the success_file to mark hashes that have been sucessfully submitted alread
        """
        self.success_file = success_file
        self.submission_file_prefix = submission_file_prefix

        # Used to track submission status
        self.num_in_progress = 0
        self.sub_time = datetime.datetime.now().timestamp()

        # Load up the hashes that have already been submitted
        self.parse_sucess_file(success_file, hash_list)

    def parse_sucess_file(self, success_file, hash_list):
        """
        Parses the "success_file" to identify hashes that have been sucessfully submitted
        and then updates hash_list with the results

        Inputs:
            success_file: (String) The file that contains all the hashes sucessfully submitted
            This way we don't resubmit them accidently

            submission_file: (String) The file to save password submissions to

            confirmation_file: (String) The file to read in confirmed and accepted submissions from

            hash_list: (HashList) The list of all hashes. Passing it in here to update
            them from the success_file to mark hashes that have been sucessfully submitted alread

        Returns:
            success: (Boolean)
                True: Everything Worked
                False: There was a problem
        """
        try:
            with open(success_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line not in hash_list.hash_lookup:
                        print(f"Warning: {line} not in the loaded hash list but it looks like we submitted it")
                    else: 
                        hash_id = hash_list.hash_lookup[line]
                        hash_list.sub_lookup[hash_id] = 2

        except FileNotFoundError:
            # The success_file hasn't been created but that isn't a problem, it just means
            # we haven't submitted any hashes and gotten a response yet
            return True
        except Exception as msg:
            print(f"Error parsing the success_file for submissions: {msg}")
            return False
        
        return True
    
    def create_submission(self, hash_list):
        """
        Creates a submission of hashes

        Inputs:

            hash_list: (HashList) The list of all hashes. Passing it in here to update
            them from the success_file to mark hashes that have been sucessfully submitted alread

        Returns:
            submit_results: (String) The list to encrypt and submit
                Will return None if there are no hashes to submit or if the in progress hashes haven't been
                acknowledged yet
        """
        if self.num_in_progress != 0:
            print("Error: You still have in-progress hashes that have not been acknowledged")
            print("Either clear the list or process an acknowledgement from KoreLogic")
            return None
        
        submit_results = []
        for hash_id, status in hash_list.sub_lookup.items():
            # Hasn't been submitted yet
            if status == 0:
                # If it has a crack
                if hash_list.hashes[hash_id].plaintext:
                    # Now check to make sure hash_type is supported for the contest
                    hash_type = hash_list.type_lookup[hash_id]
                    if hash_list.type_info[hash_type]['score']:
                        # Mark it pending, and add it to the list to submit
                        hash_list.sub_lookup[hash_id] = 1
                        self.num_in_progress += 1
                        submit_results.append(f"{hash_list.hashes[hash_id].hash}:{hash_list.hashes[hash_id].plaintext}")

        # Save the results if there are any
        if len(submit_results) != 0:
            self.sub_time = datetime.datetime.now().timestamp()
            # Figure out the filename to save a backup copy of the results
            sub_number = 1
            while True:
                save_filename = f"{self.submission_file_prefix}_{sub_number}.sav"
                if os.path.isfile(save_filename):
                    sub_number += 1
                else:
                    break

            try:
                with open(save_filename, "w+") as save_file:
                    for line in submit_results:
                        save_file.write(f"{line}\n")

            except Exception as msg:
                print(f"Warning: Issue creating backup submission file {save_filename}")
                print(f"Error: {msg}")

        # Return the results as a string with newlines between each item        
        return "\n".join(submit_results)
    

    def validate_submission(self, korelogic_msg, hash_list, force=False):
        """
        Creates a submission of hashes

        Inputs:

            korelogic_msg: (String) The acknowledgement message from KoreLogic

            hash_list: (HashList) The list of all hashes. Passing it in here to update
            them from the success_file to mark hashes that have been sucessfully submitted alread

        Returns:
            success: (Boolean)
                True: It worked correctly
                False: It did not work correctly
        """
        lines = korelogic_msg.split("\n")
        if len(lines) < 9:
            print("Hmm, something is wrong/different with the korelogic submission acknowledgement message")
            print("You might want to look into this")
            return False
        
        timestamp = lines[2].split("Timestamp: ")[1]
        ack_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d_%H:%M:%S %Z").timestamp()

        if ack_time < self.sub_time:
            print("It looks like this acknowledgment is for an older submission than the current one")
            print("Skipping this acknowledgement")
            if not force:
                return False
        
        new_cracks = int(lines[3].split("New cracks: ")[1])
        lines_received = int(lines[4].split("Lines received: ")[1])
        well_formed = int(lines[5].split("Well-formed: ")[1])
        repeats = int(lines[6].split("Repeats from previous submissions: ")[1])

        if lines_received != self.num_in_progress:
            print(f"Warning: The number of lines received was: [{lines_received}] but we submitted: [{self.num_in_progress}]")
            print("---------------")
            print(f"new_cracks: [{new_cracks}]")
            print(f"lines_received: [{lines_received}]")
            print(f"well_formed: [{well_formed}]")
            print(f"repeats: [{repeats}]")
            
            if not force:
                return False
        
        if new_cracks != lines_received:
            print(f"Warning: There was some invalid data submitted to Korelogic")
            print(f"new_cracks: [{new_cracks}]")
            print(f"lines_received: [{lines_received}]")
            print(f"well_formed: [{well_formed}]")
            print(f"repeats: [{repeats}]")
            
            if not force:
                return False

        # Save the hash to the success file and change from pending to submitted
        try:
            with open(self.success_file, "a+") as file:
                for hash_id, status in hash_list.sub_lookup.items():
                    if status == 1:
                        hash_list.sub_lookup[hash_id] = 2
                        file.write(f"{hash_list.hashes[hash_id].hash}\n")
        except Exception as msg:
            print(f"Error: Could not write to the success file: {msg}")
            return False

        return True
