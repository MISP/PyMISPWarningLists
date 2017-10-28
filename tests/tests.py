#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from pymispwarninglists import WarningLists, EncodeWarningLists
from glob import glob
import os
import json


class TestPyMISPWarningLists(unittest.TestCase):

    def setUp(self):
        self.warninglists = WarningLists()

    def test_dump_warninglists(self):
        warninglists_from_files = {}
        for warninglist_file in glob(os.path.join(self.warninglists.root_dir_warninglists, '*', 'list.json')):
            with open(warninglist_file, 'r') as f:
                warninglist = json.load(f)
            warninglists_from_files[warninglist['name']] = warninglist
        for name, w in self.warninglists.items():
            out = w._json()
            self.assertDictEqual(out, warninglists_from_files[w.name])

    def test_validate_schema_warninglists(self):
        self.warninglists.validate_with_schema()

    def test_json(self):
        for w in self.warninglists.values():
            json.dumps(w, cls=EncodeWarningLists)
