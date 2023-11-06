#!/usr/bin/env python3


"""
Unit tests for SessionMgr
"""


import unittest
from unittest.mock import patch, mock_open
import io
import sys

# Functions and classes to tests
from ..session_mgr import SessionMgr
from ..config_mgmt import load_config


class Test_SessionMgr(unittest.TestCase):
    """
    Responsible for testing SessionMgr and related functionality
    """

    def test_load_config(self):
        """
        Basic checks for loading a config file
        Putting this here so I can mock the results for calls to
        SessionMgr in later tests
        """

        # Suppress stdout to clean up unittest output (since there will be a lot of expected/caused failures
        suppress_text = io.StringIO()
        sys.stdout = suppress_text

        # Test invalid data loaded
        test_data = "bad_data"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            config = load_config("test_config")
        assert not config

        # Test invalid key in the YAML
        test_data = "---\n  bad_value:\n    bad_subvalue: test"
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            config = load_config("test_config")
        assert not config

        # Unsupress stdout
        sys.stdout = sys.__stdout__

        # Test valid YAML
        test_data = '---\n  jtr_config:\n    path: "test_path"'
        with unittest.mock.patch('builtins.open', new_callable=mock_open, read_data=test_data) as mocked_file:
            config = load_config("test_config")
        assert config == {'jtr_config':{'path':'test_path'}}

    def test_init_session_mgr(self):
        """
        Checks to make sure that SessionMgr can load configs
        """
        
        # Suppress stdout to clean up unittest output (since there will be a lot of expected/caused failures
        suppress_text = io.StringIO()
        sys.stdout = suppress_text

        # Check to make sure the SessionMgr throws and Exception if it has an invalid
        # config fiile
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={}) as load_config:
            self.assertRaises(Exception, SessionMgr, "test.yml")

        # Check to make sure the SessionMgr works with a valid config (no challenge files)
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={'jtr_config':{'path':'test_path'}}) as load_config:
            sm = SessionMgr("test.yml")

        # Unsupress stdout
        sys.stdout = sys.__stdout__

    def _setup_basic_hashlist(self, hl):
        """
        Helper Function to initialize a basic hashlist with two types
        """
        hl.add_type("type1", "type1", "1337", "high")
        hl.add_type("type2", "type2", "31337", "high")
        
        hl.add("pw1_type1", type="type1", plaintext=None)
        hl.add("pw2_type1", type="type1", plaintext=None)
        hl.add("pw3_type2", type="type2", plaintext=None)
        hl.add("pw4_type2", type="type2", plaintext=None)
        return

    def _setup_basic_targetlist(self, tl, hl):
        """
        Helper Function to initialize a basic targetlist with two targets
        """
        
        metadata = {'user':'user1', 'city':'boston'}
        hashes = [hl.hash_lookup["pw1_type1"], hl.hash_lookup["pw3_type2"]]
        tl.add(metadata, hashes)

        metadata = {'user':'user2', 'city':'boston'}
        hashes = [hl.hash_lookup["pw2_type1"], hl.hash_lookup["pw4_type2"]]
        tl.add(metadata, hashes)

        return

    def test_session_mgr_create_left_list(self):
        """
        Checks how session_mgr creates left lists
        """

        # Load SessionMgr works with a valid config (no challenge files)
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={'jtr_config':{'path':'test_path'}}) as load_config:
            sm = SessionMgr("test.yml", load_challenge=False)

        # Setup hashlist with no cracks
        self._setup_basic_hashlist(sm.hash_list)

        # Test create left list with no filter
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_left_list(is_jtr=False, file_name="test.list")
            mocked_file().write.assert_any_call("pw1_type1\n")
            mocked_file().write.assert_any_call("pw2_type1\n")
            mocked_file().write.assert_any_call("pw3_type2\n")
            mocked_file().write.assert_any_call("pw4_type2\n")
            assert mocked_file().write.call_count == 4

        # Test to make sure hashes with plaintext are excluded
        sm.hash_list.add("pw1_type1", plaintext="cracked1")
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_left_list(is_jtr=False, file_name="test.list")
            mocked_file().write.assert_any_call("pw2_type1\n")
            mocked_file().write.assert_any_call("pw3_type2\n")
            mocked_file().write.assert_any_call("pw4_type2\n")
            assert mocked_file().write.call_count == 3

        # Test to make sure hash_type is checked properly
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_left_list(is_jtr=False, file_name="test.list", hash_type="type2")
            mocked_file().write.assert_any_call("pw3_type2\n")
            mocked_file().write.assert_any_call("pw4_type2\n")
            assert mocked_file().write.call_count == 2

        # Test to make sure filter doesn't accidently exclude anything
        self._setup_basic_targetlist(sm.target_list, sm.hash_list)
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_left_list(is_jtr=False, file_name="test.list", filter={"city":"boston"})
            mocked_file().write.assert_any_call("pw2_type1\n")
            mocked_file().write.assert_any_call("pw3_type2\n")
            mocked_file().write.assert_any_call("pw4_type2\n")
            assert mocked_file().write.call_count == 3

        # Test to make sure filter does exclude things
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_left_list(is_jtr=False, file_name="test.list", filter={"user":"user2"})
            mocked_file().write.assert_any_call("pw2_type1\n")
            mocked_file().write.assert_any_call("pw4_type2\n")
            assert mocked_file().write.call_count == 2

    def test_session_mgr_create_cracked_list(self):
        """
        Checks how session_mgr creates cracked lists
        """

        # Load SessionMgr works with a valid config (no challenge files)
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={'jtr_config':{'path':'test_path'}}) as load_config:
            sm = SessionMgr("test.yml", load_challenge=False)

        # Setup hashlist with no cracks
        self._setup_basic_hashlist(sm.hash_list)

        # Test create cracked list with no filter (no passwords should be outputted)
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_cracked_list(file_name="test.list")
            assert mocked_file().write.call_count == 0

        # Now make a cracked password and see that it gets outputted
        sm.hash_list.add("pw1_type1", plaintext="cracked1")
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_cracked_list(file_name="test.list")
            mocked_file().write.assert_any_call("cracked1\n")
            assert mocked_file().write.call_count == 1

        # Test to make sure hash_type is checked properly
        sm.hash_list.add("pw2_type1", plaintext="cracked2")
        sm.hash_list.add("pw3_type2", plaintext="cracked3")
        sm.hash_list.add("pw4_type2", plaintext="cracked4")
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_cracked_list(file_name="test.list", hash_type="type2")
            mocked_file().write.assert_any_call("cracked3\n")
            mocked_file().write.assert_any_call("cracked4\n")
            assert mocked_file().write.call_count == 2

        # Test to make sure filter doesn't accidently exclude anything
        self._setup_basic_targetlist(sm.target_list, sm.hash_list)
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_cracked_list(file_name="test.list", filter={"city":"boston"})
            mocked_file().write.assert_any_call("cracked1\n")
            mocked_file().write.assert_any_call("cracked2\n")
            mocked_file().write.assert_any_call("cracked3\n")
            mocked_file().write.assert_any_call("cracked4\n")
            assert mocked_file().write.call_count == 4

        # Test to make sure filter does exclude things
        with unittest.mock.patch('builtins.open', new_callable=mock_open) as mocked_file:
            sm.create_cracked_list(file_name="test.list", filter={"user":"user2"})
            mocked_file().write.assert_any_call("cracked2\n")
            mocked_file().write.assert_any_call("cracked4\n")
            assert mocked_file().write.call_count == 2

    def test_session_mgr_status_prints(self):
        """
        Checks some basic prints that StatusMgr does
        """

        # Load SessionMgr works with a valid config (no challenge files)
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={'jtr_config':{'path':'test_path'}}) as load_config:
            sm = SessionMgr("test.yml", load_challenge=False)

        # Test out print_status()
        self._setup_basic_hashlist(sm.hash_list)
        print()
        print("Testing SessionMgr print_status()")
        sm.print_status()

        sm.hash_list.add("pw1_type1", plaintext="cracked1")
        print()
        print("Testing SessionMgr print_status()")
        sm.print_status()

        # Test printing metadata
        self._setup_basic_targetlist(sm.target_list, sm.hash_list)

        print()
        print("Testing SessionMgr print_metadata_categories()")
        sm.print_metadata_categories()

        # Test printing metadata items
        print()
        print("Testing SessionMgr print_metadata_items()")
        sm.print_metadata_items("city")

        # Test printing the score
        print()
        print("Testing SessionMgr print_score() when score is not defined")
        sm.print_score()

        print()
        print("Testing SessionMgr print_score()")
        sm.hash_list.init_scores({'type1':10, 'type2':20})
        sm.print_score()

        # Test printing all plaintexts (by hash type)
        print()
        print("Testing print_all_plaintext(). Sorted by hash type")
        sm.print_all_plaintext(meta_fields=['user','city'])

        # Test printing all plaintexts (sorted by city)
        print()
        print("Testing print_all_plaintext(). Sorted by city")
        sm.print_all_plaintext(sort_field='city', meta_fields=['user'])
    

    def test_session_mgr_pie_graph_metadata(self):
        """
        Checks the pie graph of the metadata functionality
        """
        # Load SessionMgr works with a valid config (no challenge files)
        with unittest.mock.patch('lib_framework.session_mgr.load_config', return_value={'jtr_config':{'path':'test_path'}}) as load_config:
            sm = SessionMgr("test.yml", load_challenge=False)

        # Set up a couple of basic hashes
        self._setup_basic_hashlist(sm.hash_list)
        self._setup_basic_targetlist(sm.target_list, sm.hash_list)
        sm.pie_graph_metadata("city", has_plaintext=False, top_x=None)

