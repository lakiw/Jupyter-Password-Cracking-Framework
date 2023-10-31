#!/usr/bin/env python3


"""
Unit tests for PWCrackerMGR (Generic Top Level Manager)
"""


import unittest
import io
import sys
from unittest.mock import patch, mock_open

# Functions and classes to tests
from ..pw_cracker_mgr import PWCrackerMgr

# Supporting classes
from ..hash import HashList


class Test_PWCrackerMgr(unittest.TestCase):
    """
    Responsible for testing the generic PWCrackerMgr
    """

    def _helper_create_hashlist(self):
        hl = HashList()
        hl.add_type("test", "test", "1337", "high")
        # Add the hash without a plaintext
        hl.add("abc123", type="test", plaintext=None)
        return hl

    def test_is_potfile(self):
        """
        Checks the potfile detection logic
        """
    
        cracker_mgr = PWCrackerMgr({'main_pot_file':"test.pot"})

        # Suppress stdout to clean up unittest output (since there will be a lot of expected/caused failures
        suppress_text = io.StringIO()
        sys.stdout = suppress_text

        # Various failures that should not look like pot files
        
        # Bad filename
        assert not cracker_mgr.is_potfile("test.po")

        # Invlaid data
        test_data = "foo\nbar\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert not cracker_mgr.is_potfile("test.pot")

        # Empty pot file (no data but still valid. Aka haven't cracked any hashes yet)
        test_data = ""
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert cracker_mgr.is_potfile("test.pot")

        # Valid data
        test_data = "hash1:test1\nhash2:test2\n"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert cracker_mgr.is_potfile("test.pot")

        # Unsupress stdout
        sys.stdout = sys.__stdout__

    def test_load_potfile(self):
        """
        Checks the ability to correctly read in a potfile
        """
        cracker_mgr = PWCrackerMgr({'main_pot_file':"test.pot"})

        # Test loading an empty potfile
        hl = self._helper_create_hashlist()
        test_data = ""
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert cracker_mgr.load_potfile("test.pot", hl) == 0
            assert hl.hashes[hl.hash_lookup['abc123']].plaintext == None

        # Test loading one cracked password
        hl = self._helper_create_hashlist()
        test_data = "abc123:cracked"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert cracker_mgr.load_potfile("test.pot", hl) == 1
            assert hl.hashes[hl.hash_lookup['abc123']].plaintext == 'cracked'

        # Test loading a new password
        hl = self._helper_create_hashlist()
        test_data = "new_pw:cracked"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            # First make sure the new hash isn't added if update_only is True
            assert cracker_mgr.load_potfile("test.pot", hl, update_only=True) == 0

            # Now make sure it gets added if update_only is False
            assert cracker_mgr.load_potfile("test.pot", hl, update_only=False) == 1
            assert hl.hashes[hl.hash_lookup['new_pw']].plaintext == 'cracked'

    def test_update_potfile(self):
        """
        Checks the ability to correctly update a potfile with new cracks
        """
        cracker_mgr = PWCrackerMgr({'main_pot_file':"test.pot"})

        # Test updating an empty potfile but there are no new cracked passwords
        hl = self._helper_create_hashlist()
        test_data = ""
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data):
            assert cracker_mgr.update_potfile("test.pot", hl) == 0

        # Test updating an empty potfile but with one new cracked passwords
        hl = self._helper_create_hashlist()
        hl.add("abc123",plaintext="cracked")
        test_data = ""
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            assert cracker_mgr.update_potfile("test.pot", hl) == 1
            mocked_file().write.assert_called_once_with("abc123:cracked")

        # Test updating a potfile with existing cracked hashes but with one new cracked passwords
        hl = self._helper_create_hashlist()
        hl.add("abc123",plaintext="cracked")
        test_data = "old_hash:123"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            assert cracker_mgr.update_potfile("test.pot", hl) == 1
            mocked_file().write.assert_called_once_with("abc123:cracked")

        # Test updating a potfile with existing cracked hashes and those hashes are in the main cracked passwords
        hl = self._helper_create_hashlist()
        hl.add("abc123",plaintext="cracked")
        test_data = "abc123:cracked"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            assert cracker_mgr.update_potfile("test.pot", hl) == 0