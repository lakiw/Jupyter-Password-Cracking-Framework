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
        self.seperator = ":"

    def print_command(self):
        """
        Prints out the "default" options for running the password cracker
        so that pot files and log files are generated in a manner this framework expects

        Inputs:
            None

        Returns:
            command: (STR) The command that should be used to generate appropriate
            potfiles and logfiles
        """
        command_parts = []
        if self.path:
            command_parts.append(f"{self.path}/hashcat")
        else:
            command_parts.append("hashcat")

        if self.main_pot_file:
            command_parts.append(f" -o {self.main_pot_file}")

        if self.log_directory:
            command_parts.append(f" --debug-file {self.log_directory}hc_session")
            command_parts.append(f" --debug-mode 5")
            command_parts.append(f" -p '{self.seperator}'")

        command = "".join(command_parts)

        print(command)

        return command

    def is_logfile(self, filename, format=5, delimeter=":", verbose=False):
        """
        Function that says if this log file is the correct format for this
        password cracker manager

        Dev Note: Only supporting Hashcat Debug file format 5

        Debug Format 5: Original-Word:Finding-Rule:Processed-Word:Wordlist

        Inputs:
            filename: (str) The full path and filename of the log to parse

            format: (int) The Hashcat debug format to use (currently only '5' is supported)

        Returns:
            success: (Bool) True if this looks like a log file for this program
                            False if an error occured or this is not a supported format
        """

        # Putting this check in here to make it easier to support other modes in the future
        if format not in [5]:
            print(f"Error: Only supporting debug log files of type '5'. You specified type {format}")
            return False

        try:
            with open(filename) as logfile:
                line = logfile.readline().strip()

                # Quick bail out to ensure that we aren't parsing timestamped files
                # Specifically looking for JtR timestamped files
                if line.startswith("0:00:00:00"):
                    return False

                while line:
                    result = self._parse_hc_log_line(line, format, delimeter, verbose)
                    if not result:
                        return False
                    line = logfile.readline().strip()
            return True
        
        except FileNotFoundError:
            print(f"Error: Could not find the file:{filename}")
        return False
    
    def _parse_hc_log_line(self, line, format=5, delimeter=":", verbose=True):
        """
        Returns a dictionary of the log line contents
        If it is not a valid Hashcat log line, returns an empty dictionary

        Dev Note: Only supporting Hashcat Debug file format 5

        Debug Format 5: Original-Word:Finding-Rule:Processed-Word:Wordlist

        Inputs:

            line: (str) The Hashcat debug line to parse

            format: (int) The Hashcat debug format to use (currently only '5' is supported)

            verbose: (bool) If True, will print out parsing errors. Set this up so that it
            can be used for logfile identification without spamming a bunch of messages

        Returns:
            contents: (Dic) The parsed contents of the line
                {
                    'original_word':"WORD",
                    'finding_rule':"RULE",
                    'processed_word':"WORD",
                    'wordlist':"WORDLIST",
                    'uncategorized':"FULL_LINE_NOT PARSED"
                }
        """
        contents = {}

        # Debug mode #5
        if format == 5:
            # This can be a bit complicated since the delimeter ":" can appear in most of the items in the line
            split_line = line.split(delimeter)
            if len(split_line) < 4:
                if verbose:
                    print(f"Error: Invalid line in Hashcat debug log. Format: {format} Delimeter: [{delimeter}] Line: {line}")
                return {}

            # Handle if there were delimeters in the log line that weren't delimiters
            elif len(split_line) == 5:
                # If the delimeter is a ":" First ":" is probably a do nothing passthrough rule
                first_half = split_line[1]
                second_half = split_line[2]
                del(split_line[2])
                split_line[1] = first_half + delimeter + second_half
            
            # Ugg, it is really hard to figure out where the rest of the ":" properly belong.
            # Aka it could be appending a ":", the ":" could be in a wordlist, etc
            if len(split_line) > 5:
                contents['uncategorize'] = line
                if verbose:
                    print(f"Extra '{delimeter}' found in log file. Framework does not know how to parse it")
                    print(f"    {line}")
            else:
                contents['original_word'] = split_line[0]
                contents['finding_rule'] = split_line[1]
                contents['processed_word'] = split_line[2]
                contents['wordlist'] = split_line[3]

        else:
            print(f"Error: Hashcat debug format not supported by this framework: {format}")

        return contents