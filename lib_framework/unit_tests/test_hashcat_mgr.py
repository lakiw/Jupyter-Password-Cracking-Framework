#!/usr/bin/env python3


"""
Unit tests for the Hashcat PWCrackerMGR

"""


import unittest
import io
import sys
from unittest.mock import patch, mock_open

# Functions and classes to tests
from ..hashcat_mgr import HashcatMgr
from ..session import SessionList
from ..strike import StrikeList
from ..hash import HashList

class Test_HashcatMgr(unittest.TestCase):
    """
    Responsible for testing the HashcatMgr
    """

    def test_parse_hc_log_line(self):

        hc = HashcatMgr({})

        # Suppress stdout to clean up unittest output (since there will be a lot of expected/caused failures
        suppress_text = io.StringIO()
        sys.stdout = suppress_text

        # Test wrong format handling
        line = "Original-Word:RULE:Processed-Word:Wordlist"
        result = hc._parse_hc_log_line(line, format=3, verbose=False)
        assert not result

        # Test not enough fields for format 5
        line = "Stuff:stuff"
        result = hc._parse_hc_log_line(line, format=5, verbose=False)
        assert not result

        # Unsupress stdout
        sys.stdout = sys.__stdout__

        # Test basic case
        line = "Original-Word:RULE:Processed-Word:Wordlist"
        result = hc._parse_hc_log_line(line, format=5)
        assert result['original_word'] == "Original-Word"
        assert result['finding_rule'] == "RULE"
        assert result['processed_word'] == "Processed-Word"
        assert result['wordlist'] == "Wordlist"

        # Test extra ":" for the do nothing rule
        line = "Original-Word:::Processed-Word:Wordlist"
        result = hc._parse_hc_log_line(line, format=5)
        assert result['original_word'] == "Original-Word"
        assert result['finding_rule'] == ":"
        assert result['processed_word'] == "Processed-Word"
        assert result['wordlist'] == "Wordlist"

        # Test extra ":" for the do nothing rule where it falls in the middle of a rule
        line = "Original-Word:-5:$1:Processed-Word:Wordlist"
        result = hc._parse_hc_log_line(line, format=5)
        assert result['original_word'] == "Original-Word"
        assert result['finding_rule'] == "-5:$1"
        assert result['processed_word'] == "Processed-Word"
        assert result['wordlist'] == "Wordlist"

    def test_parse_logline(self):
        """
        Checks that HashcatManager parsed a log line correctly.

        Note: A lot of overlap here with the test_identigy_logfile tests
        """
        hc = HashcatMgr({})

        # Test basic working
        line = "word:rule:pass:wordlist"
        result = hc._parse_hc_log_line(line, format=5, delimeter=":", verbose=True)
        assert result == {'original_word': 'word', 'finding_rule': 'rule', 'processed_word': 'pass', 'wordlist': 'wordlist'}

        # Test different delimeter
        line = "word!rule!pass!wordlist"
        result = hc._parse_hc_log_line(line, format=5, delimeter="!", verbose=True)
        assert result == {'original_word': 'word', 'finding_rule': 'rule', 'processed_word': 'pass', 'wordlist': 'wordlist'}

        # Test failed number of items
        line = "word:rule:pass"
        result = hc._parse_hc_log_line(line, format=5, delimeter=":", verbose=False)
        assert not result

    def test_identify_logfile(self):
        """
        Checks that HashcatManager identifies HC logfiles correctly
        """
        hc = HashcatMgr({})

        # Test valid logfile
        test_data = "word:rule:pass:wordlist\nword2:rule2:pass2:wordlist\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert hc.is_logfile("test.log")

        # Test invalid logfile for a JtR file
        test_data = test_data = "0:00:00:00 Starting a new session\n0:00:00:00 Loaded a total of 10812 password hashes with no different salts\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert not hc.is_logfile("test.log")

        # Test invalid logfile wrong format
        test_data = test_data = "test:$1:test1\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert not hc.is_logfile("test.log", verbose=False)

        # Test log with a ":" in the rule
        test_data = test_data = "test::$1:test1:wordlist\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert hc.is_logfile("test.log")