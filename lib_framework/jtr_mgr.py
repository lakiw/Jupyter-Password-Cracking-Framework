"""
Contains functionality for managing John the Ripper password cracker

Not indended to run full cracking sessions. Functionality
is more for syncing pot files, identifying cracked hashes,
and running simple loopback attacks.
"""


# Using this to parse logfiles that may have been imported from a different system/os
from pathlib import Path 

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
        Converts the hash from a normalized format to the the version 
        JtR expects.

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
    
    def read_logfile(self, filename, session_list, strike_list, hash_list):
        """
        Reads the JtR logfiles

        Note: There is a lot of complications when it comes to mapping a cracked hash in the JtR logfile
        to a hash in this framework. That's because JtR logs the username associated with a cracked
        password and not the hash itself. If a username is not specificed it lists it as a '?' which makes
        it very difficult to figure out what was actually cracked. An additional config option can be specified
        in the JtR config to also output the cracked password to the log, but that can cause problems and
        isn't always accurate.

        This function will see if a username has been specified and attempt to match it up to a specific 
        hash so the strikes can be correctly assigned to that hash. If that fails, strikes will be assigned 
        to the 'None' hash. Other portions of this framework will be responsible for creating JtR hashfiles
        that have approprite usernames assigned to them (by default the username will be the hash id in this
        framework).

        Note 2: There is very little type checking, sanity checking, error handling in this. I'd
        recommend using a try/except around calls to this function. I didn't want to supress errors
        while I'm working on developing this function. Also, there's a million ways the logfile
        could be different from what I expect.

        Inputs:
            filename: (str) The full path and filename of the log to parse

            session_list: (SessionList) Keeps track of password cracking sessions.
            Mostly used for JtR logs

            strike_list: (StrikeList) Keeps track of sucessful rules

        Returns:
            success: (Bool) True if this completed properly
                            False if an error occured
        """
        # First check to make sure the logfile is a JtR logfile
        if not self.is_logfile(filename):
            print(f"Error: The file {filename} is not a JtR formatted log file")
            return False

        # Open the logfile up for reading
        with open(filename) as logfile:

            # Parsing the logfile line by line since these logfiles can get huge. This provides
            # a future way to bail out or only read the tail of it in the future.
            line = True

            # Using this to do a sanity check on the log file format
            active_session = False

            # Information for the actual session
            compleated = False
            session_info = {
                'mode':None,
                'options':{}
                }
            
            # Used to match up cracks with what attack was running
            cur_attack = None
            cur_rule = None
            cur_wordlist = None
            cur_strikes = []

            # Running hashed value to assign strikes that don't have a hash associated with them
            # This way if the log file is run again, no duplicate strikes will be created
            running_hash = None

            while line:

                # Doing this at the top, so if I select "continue" to skip a line then I don't have to
                # remember to put the readline there as well
                line = logfile.readline().strip()

                # Skip blank lines
                if len(line) == 0:
                    continue

                # A new session was detected in the file
                if line == "0:00:00:00 Starting a new session":
                    active_session = True
                    continue
                # An unexpected line was encountered
                elif not active_session:
                    print(f"Unexpected line found in logfile {logfile}. Line: {line}")
                    continue

                # Split up the line to extract the timestamp
                split_line = line.split(":")

                # If there wasn't a timestamp
                if len(split_line) < 4:
                    print(f"Unexpected line found in logfile {filename}. Line: {line}")
                    continue

                time_day = int(split_line[0])
                time_hour = int(split_line[1])
                time_minute = int(split_line[2])

                # Split second from the rest of the log message. Also need to combine any 3+ index
                # in case there was a ":' in the regular log
                rest_line = split_line[3]
                if len(split_line) > 4:
                    for x in split_line[4:]:
                        rest_line += ":" + x
                split_line = rest_line.split(" ", 1)
                if len(split_line) != 2:
                    print(f"Unexpected line found in logfile {filename}. Line: {line}")
                    continue

                time_second = int(split_line[0])
                log_msg = split_line[1]

                # Update the running hash here. This is independent of the time so if the
                # exact same attack is run again, it "might" detect duplicates.
                running_hash = hash(f"{log_msg}{running_hash}")

                # Now parse the various log messages

                # If the session was finished
                if log_msg.strip() == "Session aborted" or log_msg.strip() == "Session completed":
                    if log_msg.strip() == "Session completed":
                        compleated = True
                    
                    total_time = time_day * (24 * 60 * 60) + time_hour * (60 * 60) + time_minute * 60 + time_second
                    session_info['options']['total_time'] = total_time
                    session_id = session_list.add(self, session_info, compleated=compleated, check_duplicates=True)

                    # Add strikes to the session
                    for strike_id in cur_strikes:
                        session_list.sessions[session_id].add_strike(strike_id)
                    
                    active_session = False
                    compleated = False
                    cur_attack = None
                    cur_rule = None
                    cur_wordlist = None
                    cur_strikes = []
                    running_hash = None
                    session_info =  {
                        'mode':None,
                        'options':{}
                        }

                # Lists the number of hashes loaded
                elif log_msg.strip().startswith("Loaded a total of "):
                    split_line = log_msg.split("Loaded a total of ")
                    num_loaded = int(split_line[1].split()[0].strip())
                    session_info['options']['num_loaded'] = num_loaded
                
                # Get the hash type (without having to parse the command line)
                elif log_msg.strip().startswith("- Hash type: "):
                    split_line = log_msg.strip().split("- Hash type: ")
                    # The hash type can have extra info following a "," or a "("
                    split_line = split_line[1].split(",")
                    split_line = split_line[0].split(" (")
                    session_info['hash_type'] = split_line[0]

                # Specifies the max accepted guess length (Helpful when targeting passphrases
                elif log_msg.strip().startswith("- Will reject candidates longer than "):
                    split_line = log_msg.split("- Will reject candidates longer than ")
                    # Strip off the bytes at the end
                    split_line = split_line[1].split()
                    # Long variable name, but I want people to know exactly what this is
                    session_info['options']['max_guess_size_bytes'] = int(split_line[0])

                # Get the command line. Eventually I'll want to parse this further
                elif log_msg.strip().startswith("Command line: "):
                    split_line = log_msg.split("Command line: ")
                    session_info['options']['command_line'] = split_line[1]

                # The following few checks look for the mode the cracker is run in
                # Eventually I can pull this from the command line too, but this will
                # be a good stopgap until I add that functionality
                elif log_msg.strip().startswith('Proceeding with "single crack" mode'):
                    session_info['mode'] = "single"
                    cur_attack = "single"
                elif log_msg.strip().startswith("Proceeding with wordlist mode"):
                    # Gets a bit weird since I want to classify this as a single session, but this
                    # is the second default attack run in JtR's Single mode
                    if not session_info['mode']:
                        session_info['mode'] = "wordlist"
                    cur_attack = "wordlist"
                
                # Incremental mode
                elif log_msg.strip().startswith('Proceeding with "incremental" mode: '):
                    session_info['mode'] = "incremental"
                    cur_attack = "incremental"

                    # Get the incremental training set being used
                    split_line = log_msg.strip().split('Proceeding with "incremental" mode: ')
                    cur_rule = split_line[1]

                # Get the wordlist being used
                elif log_msg.strip().startswith("- Wordlist file: "):
                    split_line = log_msg.strip().split("- Wordlist file: ")
                    # Just get the dictionary name
                    cur_wordlist = Path(split_line[1]).name
                
                # Get the encoding of input characters. Might be relevant
                # for certain challenges
                elif "input encoding enabled" in log_msg.strip():
                    split_line = log_msg.strip().split(" input encoding enabled")
                    split_line = split_line[0].split("- ")
                    session_info['options']['encoding'] = split_line[1]

                # It might be helpful to see how many rules were run to identify
                # how useful/effecient different mangling rule sets are
                elif " preprocessed word mangling rules" in log_msg.strip():
                    split_line = log_msg.strip().split(" preprocessed word mangling rules")
                    split_line = split_line[0].split("- ")
                    session_info['options']['num_rules'] = int(split_line[1])

                # Mangling ruleset used
                elif log_msg.strip().startswith("- Rules: "):
                    split_line = log_msg.strip().split("- Rules: ")
                    session_info['options']['ruleset'] = split_line[1]

                # Parse the rules as they are processed
                elif log_msg.strip().startswith("- Rule #"):
                    # Get the original rule vs. what's being processed.
                    # Strip the Rule # from the string
                    split_line = log_msg.split(": '", 1)
                    split_line = split_line[1]

                    # Remove the JtR fixup info
                    split_line = split_line.split("' accepted as '")

                    # Remove the "rejected" from rejected rules. This shouldn't matter
                    # since rejected rules should not crack passwords...
                    split_line = split_line[0]
                    split_line = split_line.split("' rejected")

                    cur_rule = split_line[0]

                # No rules specified so it applies a default ":" rule to the wordlist
                elif log_msg.strip().startswith("- No word mangling rules"):
                    cur_rule = ":"

                # A hash was cracked
                elif log_msg.strip().startswith("+ Cracked"):

                    # Get the username and strip out the plaintext if that was logged
                    split_line = log_msg.strip().split("+ Cracked ")
                    # The plaintext might have a ":" in it so only split on the first one that
                    # divides the username from the plaintext
                    split_line = split_line[1].split(":",1)
                    username = split_line[0]
                    plaintext = None
                    if len(split_line) != 1:
                        plaintext = split_line[1]

                    # Check if the username is a hash_id or not
                    hash_id = None
                    # A username wasn't specified
                    if username == "?":
                        username = None
                    elif username.isdigit():
                        hash_id = int(username)
                        # Check if the hash_id is legitamite
                        if hash_id not in hash_list.hashes:
                            # hash_id wasn't found so set it to be none again
                            # and treat it as a straight username
                            hash_id = None

                    # Create the strike
                    if cur_attack in ["wordlist", "single"]:
                        strike_id = strike_list.add(self, hash_id, {"attack":cur_attack, "rule":cur_rule, "wordlist":cur_wordlist, "duplicate_detection_id":running_hash})
                    elif cur_attack == "incremental":
                        strike_id = strike_list.add(self, hash_id, {"attack":cur_attack, "mode":cur_rule, "duplicate_detection_id":running_hash})

                    if strike_id not in cur_strikes:
                        cur_strikes.append(strike_id)

                # Lines that are currently being ignored. (Doing it this way to make it easier to
                # identify interesting lines I haven't handled yet.
                elif log_msg.strip().startswith("- Candidate passwords will be buffered and tried in chunks of"):
                    continue
                elif log_msg.strip().startswith("- memory mapping wordlist"):
                    continue
                elif log_msg.strip().startswith("- Allocated"):
                    continue
                elif log_msg.strip().startswith("- Processing the remaining buffered candidate passwords, if any"):
                    continue
                elif log_msg.strip().startswith("- Passwords will be stored "):
                    continue
                elif log_msg.strip().startswith("- Configured to use otherwise idle processor cycles only"):
                    continue
                elif log_msg.strip().startswith("- SingleWordsPairMax used is "):
                    continue
                elif log_msg.strip().startswith("- SingleRetestGuessed = "):
                    continue
                elif log_msg.strip().startswith("- SingleMaxBufferSize = "):
                    continue
                elif log_msg.strip().startswith("- No information to base candidate passwords on"):
                    continue
                elif log_msg.strip().startswith("Enabling duplicate candidate password suppressor"):
                    continue
                elif log_msg.strip().startswith("Remaining "):
                    continue
                elif log_msg.strip().startswith("- suppressed "):
                    continue
                elif log_msg.strip().startswith("Cost "):
                    continue
                elif log_msg.strip().startswith("- Passwords in this logfile are UTF-8 encoded"):
                    continue
                # We get the actual dictionary from an earlier logfile
                elif log_msg.strip().startswith("- loading wordfile"):
                    continue
                elif log_msg.strip().startswith("- wordfile had"):
                    continue
                # I'm struggling with this one. I may want to add it back as an alternative
                # rule since it can crack a password and right now it would be misattributed
                # to the next rule
                elif log_msg.strip().startswith("- Oldest still in use is now rule"):
                    continue
                # Skip a lot of the incremental logs
                elif log_msg.strip().startswith("- Trying length "):
                    continue
                elif log_msg.strip().startswith("- Switching to length "):
                    continue
                elif log_msg.strip().startswith("- Expanding tables for length "):
                    continue
                elif log_msg.strip().startswith("- Lengths "):
                    continue
                # We're getting the the hash type from the "Hash Type" log message. So we can skip this message
                elif log_msg.strip().startswith("- Algorithm:"):
                    continue
                # Need to look into what this really means, and where stacked rules can come into play
                elif log_msg.strip().startswith("- No stacked rules"):
                    continue
                # Remove non-pertinant JtR debugging logs
                elif log_msg.strip().startswith("Disabling duplicate candidate password suppressor"):
                    continue
                # Doing this to indentify log lines I haven't set up rules to parse yet
                else:
                    print(f"{log_msg.strip()}")
                
        return True
    
    def is_logfile(self, filename):
        """
        Stub function that says if this log file is the correct format for this
        password cracker manager

        This should be implimented in the actual password manager implimentations

        Inputs:
            filename: (str) The full path and filename of the log to parse

        Returns:
            success: (Bool) True if this looks like a log file for this program
                            False if an error occured or this is not a supported format
        """

        # Just checking the first line since that has a very specific format
        try:
            with open(filename) as logfile:
                line = logfile.readline().strip()
                if line == "0:00:00:00 Starting a new session":
                    return True
        except FileNotFoundError:
            print(f"Error: Could not find the file:{filename}")
        return False
        