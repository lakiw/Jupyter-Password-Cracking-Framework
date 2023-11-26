#!/usr/bin/env python3


"""
Unit tests for StrikeList and Strike
"""


import unittest

# Functions and classes to tests
from ..strike import Strike
from ..strike import StrikeList
from ..pw_cracker_mgr import PWCrackerMgr


class Test_StrikeList(unittest.TestCase):
    """
    Responsible for testing Strike and StrikeList classes
    """

    def test_update_fist_strike(self):
        """
        Checks to make sure that a basic add to the strikelist
        works, and that it can detect duplicates
        """
        
        # Initialize the strikelist
        strike_list = StrikeList()

        # Initialize the PWCrackerMgr
        cracker_mgr = PWCrackerMgr({'main_pot_file':"test.pot"})

        # Add the strike
        details = {'mode':'0', 'wordlist':'dic0294.txt'}
        hash = 0
        assert strike_list.add(cracker_mgr, hash, details) == 0

        # Add a duplicate and make sure it doesn't get added
        assert strike_list.add(cracker_mgr, hash, details) == 0

        # Add a second entry and see that it does get added
        details = {'mode':'0', 'wordlist':'passwords.lst'}
        assert strike_list.add(cracker_mgr, hash, details) == 1


    def test_strike_lookup_fields(self):
        """
        Checks to make sure the strike fields are set up correctly
        """
        
        # Initialize the strikelist
        strike_list = StrikeList()

        # Initialize the PWCrackerMgr
        cracker_mgr1 = PWCrackerMgr({'main_pot_file':"test.pot"})
        cracker_mgr1.name = "c1"
        cracker_mgr2 = PWCrackerMgr({'main_pot_file':"test.pot"})
        cracker_mgr2.name = "c2"

        # Add the strikes
        details = {'mode':'0', 'wordlist':'dic0294.txt'}
        hash = 0
        assert strike_list.add(cracker_mgr1, hash, details) == 0

        hash = 1
        details = {'mode':'0', 'wordlist':'passwords.lst'}
        assert strike_list.add(cracker_mgr1, hash, details) == 1

        hash = 2
        details = {'mode':'0', 'wordlist':'passwords.lst'}
        assert strike_list.add(cracker_mgr2, hash, details) == 2
        details = {'mode':'0', 'wordlist':'dic0294.txt'}
        assert strike_list.add(cracker_mgr2, hash, details) == 3

        assert strike_list.tool_lookup['c1'] == [0, 1]
        assert strike_list.tool_lookup['c2'] == [2, 3]

        assert strike_list.hash_id_lookup[0] == [0]
        assert strike_list.hash_id_lookup[1] == [1]
        assert strike_list.hash_id_lookup[2] == [2, 3]