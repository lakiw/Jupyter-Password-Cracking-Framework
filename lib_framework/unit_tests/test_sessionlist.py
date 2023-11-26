#!/usr/bin/env python3


"""
Unit tests for SessionList and Sessions
"""


import unittest

# Functions and classes to tests
from ..session import SessionList
from ..session import Session
from ..pw_cracker_mgr import PWCrackerMgr


class Test_SessionList(unittest.TestCase):
    """
    Responsible for testing Session and SessionList classes
    """

    def test_update_fist_session(self):
        """
        Checks to make sure that a basic add to the sessionlist
        works, and that it can detect duplicates
        """
        
        # Initialize the sessionlist
        session_list = SessionList()

        # Initialize the PWCrackerMgr
        cracker_mgr = PWCrackerMgr({'main_pot_file':"test.pot"})

        # Add the session
        session_info = {'mode':'mask', 'hash_type':'raw-md5', 'options':{'mode':'0', 'wordlist':'dic0294'}}
        assert session_list.add(cracker_mgr, session_info, compleated=False, check_duplicates=True) == 0

        # Add a duplicate and make sure it doesn't get added
        assert session_list.add(cracker_mgr, session_info, compleated=False, check_duplicates=True) == 0

        # Add a second entry and see that it does get added
        session_info = {'mode':'mask', 'hash_type':'raw-md5', 'options':{'mode':'0', 'wordlist':'password.lst'}}
        assert session_list.add(cracker_mgr, session_info, compleated=False, check_duplicates=True) == 1
