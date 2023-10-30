#!/usr/bin/env python3


"""
Unit tests for TargetList and Target
"""


import unittest

# Functions and classes to tests
from ..target import Target
from ..target import TargetList
from ..hash import HashList


class Test_TargetList(unittest.TestCase):
    """
    Responsible for testing Target and TargetList classes
    """

    def test_update_fist_target(self):
        """
        Checks to make sure that a basic add to the targetlist
        works, and that it can detect duplicates
        """
        
        # Initialize the targetlist
        target_list = TargetList()

        # Add the target
        metadata = {'user':'test', 'city':'boston'}
        hashes = [0,1]
        assert target_list.add(metadata, hashes) == 1

        # Add a duplicate and make sure it doesn't get added
        assert target_list.add(metadata, hashes) == 0

        # Add a second entry and see that it does get added
        metadata = {'user':'matt', 'city':'boston'}
        hashes = [0]
        assert target_list.add(metadata, hashes) == 1

    def test_get_stats(self):
        """
        Checks to make sure stats returned about the target are correct
        """
    
        # Initialize the hashlist
        hl = HashList()
        hl.add_type("test", "test", "1337", "high")
        hl.add("hash1", type="test", plaintext=None)

        # Initialize the targetlist
        target_list = TargetList()
        metadata = {'user':'test', 'city':'boston'}
        hashes = [hl.hash_lookup["hash1"]]
        target_list.add(metadata, hashes)

        # Test the get_stats_target
        stats = target_list.get_stats_target(0, hl)
        assert stats['num_hashes'] == 1
        assert stats['num_cracked'] == 0

        # Test the get_stats_metadata
        stats = target_list.get_stats_metadata('city', 'boston', hl)
        assert stats['num_hashes'] == 1
        assert stats['num_cracked'] == 0

