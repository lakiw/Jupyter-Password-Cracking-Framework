#!/usr/bin/env python3


"""
Unit tests for HashList and Hash
"""


import unittest

# Functions and classes to tests
from ..hash import Hash
from ..hash import HashList


class Test_HashList(unittest.TestCase):
    """
    Responsible for testing Hash and HashList classes
    """

    def test_hash_sorting(self):
        """
        Checks to make sure Hash equality and sorting work
        """
    
        hash1 = Hash("Alpha","Plaintext")
        hash2 = Hash("Alpha")

        assert hash1 == hash2

        hash3 = Hash("Beta")
        assert hash1 != hash3
        
        assert hash1 < hash3

    def test_update_fist_hash(self):
        """
        Checks to make sure that a basic add to the hashlist
        works, and that we can update the plaintext later
        """
        
        # Initialize the hashlist
        hl = HashList()
        hl.add_type("test", "test", "1337", "high")
        assert "test" in hl.type_info

        # Add the hash without a plaintext
        hl.add("abc123", type="test", plaintext=None)
        assert hl.hashes[0].hash == "abc123"
        assert hl.hashes[0].plaintext == None
        assert hl.hash_lookup["abc123"] == 0
        assert hl.type_lookup[0] == "test"
        assert 0 in hl.type_list["test"]
        assert hl.type_info['test']['total'] == 1
        assert hl.type_info['test']['cracked'] == 0

        # Update an existing hash with a plaintext
        hl.add("abc123", plaintext="easy_peasy")
        assert hl.hashes[0].hash == "abc123"
        assert hl.hashes[0].plaintext == "easy_peasy"
        assert hl.type_info['test']['total'] == 1
        assert hl.type_info['test']['cracked'] == 1


    def test_add_three_hashes(self):
        """
        If we can add one hash, let's validate we can
        add three hashes with two different types
        """
        
        # Initialize the hashlist and types
        hl = HashList()
        hl.add_type("type1", "type1", "1337", "high")
        assert "type1" in hl.type_info
        hl.add_type("type2", "type2", "31337", "low")
        assert "type2" in hl.type_info

        # Add the three hashes
        hl.add("hash1", type="type1")
        hl.add("hash2", type="type2")
        hl.add("hash3", type="type1")

        assert hl.hashes[0].hash == "hash1"
        assert hl.hashes[0].plaintext == None
        assert hl.hash_lookup["hash1"] == 0
        assert hl.type_lookup[0] == "type1"
        assert 0 in hl.type_list["type1"]

        assert hl.hashes[1].hash == "hash2"
        assert hl.hashes[1].plaintext == None
        assert hl.hash_lookup["hash2"] == 1
        assert hl.type_lookup[1] == "type2"
        assert 1 in hl.type_list["type2"]

        assert hl.hashes[2].hash == "hash3"
        assert hl.hashes[2].plaintext == None
        assert hl.hash_lookup["hash3"] == 2
        assert hl.type_lookup[2] == "type1"
        assert 2 in hl.type_list["type1"]

    def test_update_type_from_none(self):
        """
        Don't set the hashtype and then update it later
        This is important for things like raw-md5 vs. ntlm
        """
        
        # Initialize the hashlist and types
        hl = HashList()
        hl.add_type("type1", "type1", "1337", "high")
        assert "type1" in hl.type_info

        # Add the hash with no type
        hl.add("hash1", plaintext="plain1")

        assert hl.hashes[0].hash == "hash1"
        assert hl.hashes[0].plaintext == "plain1"
        assert hl.hash_lookup["hash1"] == 0
        assert hl.type_lookup[0] == hl.unknown_type
        assert 0 in hl.type_list[hl.unknown_type]

        # Update the type
        hl.add("hash1", type="type1")

        # Check it was added to type1
        assert hl.type_lookup[0] == "type1"
        assert 0 in hl.type_list["type1"]
        assert hl.type_info["type1"]['total'] == 1
        assert hl.type_info["type1"]['cracked']== 1

        # Check that it was removed from unknown_type
        assert 0 not in hl.type_list[hl.unknown_type]
        assert hl.type_info[hl.unknown_type]['total'] == 0
        assert hl.type_info[hl.unknown_type]['cracked'] == 0