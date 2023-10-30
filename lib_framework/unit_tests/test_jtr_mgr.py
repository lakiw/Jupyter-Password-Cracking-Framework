#!/usr/bin/env python3


"""
Unit tests for JtR PWCrackerMGR

Really just checks the hash normalization functionality
"""


import unittest
import io
import sys

# Functions and classes to tests
from ..jtr_mgr import JTRMgr

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