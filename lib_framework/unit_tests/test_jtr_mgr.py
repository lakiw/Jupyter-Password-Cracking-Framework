#!/usr/bin/env python3


"""
Unit tests for JtR PWCrackerMGR

Really just checks the hash normalization functionality
"""


import unittest
import io
import sys
from unittest.mock import patch, mock_open

# Functions and classes to tests
from ..jtr_mgr import JTRMgr
from ..session import SessionList
from ..strike import StrikeList

class Test_JTRMgr(unittest.TestCase):
    """
    Responsible for testing the JTRMgr
    """

    def test_normalize_hash(self):
        """
        Checks that the $dyanamic_X$ hash identifies are properly stripped
        """
        jtr_mgr = JTRMgr({})

        # Check to see if there is no formatting then it is ok
        assert jtr_mgr.normalize_hash("test") == "test"

        # Check to remove basic dynamic formatting
        assert jtr_mgr.normalize_hash("$dynamic_1$test") == "test"

        # Suppress stdout to clean up unittest output (since there will be a lot of expected/caused failures
        suppress_text = io.StringIO()
        sys.stdout = suppress_text

        # Check malformed dynamic formatting
        assert jtr_mgr.normalize_hash("$dynamic_1test") == None
        # Unsupress stdout

        sys.stdout = sys.__stdout__

    def test_format_hash(self):
        """
        Checks that the $dyanamic_X$ hash identifies are properly stripped
        """
        jtr_mgr = JTRMgr({})

        # Test format that doesn't have a JtR format mapping
        assert jtr_mgr.format_hash("test","test_format") == "test"

        # Test raw-md5
        assert jtr_mgr.format_hash("test","raw-md5") == "$dynamic_0$test"

        # Test raw-sha1
        assert jtr_mgr.format_hash("test","raw-sha1") == "$dynamic_26$test"

    def test_identify_logfile(self):
        """
        Checks that JtRManager identifies JtR logfiles correctly
        """
        jtr_mgr = JTRMgr({})

        # Test valid logfile
        test_data = "0:00:00:00 Starting a new session\n0:00:00:00 Loaded a total of 10812 password hashes with no different salts\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert jtr_mgr.is_logfile("test.log")

        # Test invalid logfile
        test_data = "password:$1:password1:password.lst"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert not jtr_mgr.is_logfile("test.log")

    def test_read_logfile(self):
        """
        Checks that JtRManager reads logfiles properly
        """
        jtr_mgr = JTRMgr({})

        # Initialize the sessionlist
        session_list = SessionList()

        # Initialize the strikelist
        strike_list = StrikeList()

        # Test valid logfile
        assert jtr_mgr.read_logfile("../JohnTheRipper/run/john.log", session_list, strike_list)

        print("SESSIONS")
        for key, value in session_list.sessions.items():
            print(f"{key}:{value.mode}:{value.options}:{value.strike_id_list}:{value.hash_type}")
        print("STRIKES")
        for key, value in strike_list.strikes.items():
            print(f"{key}:{value.details}")
