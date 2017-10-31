#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from json import JSONEncoder
import os
import sys
import collections
from glob import glob

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


class EncodeWarningList(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, WarningList):
            return obj.to_dict()
        return JSONEncoder.default(self, obj)


class PyMISPWarningListsError(Exception):
    def __init__(self, message):
        super(PyMISPWarningListsError, self).__init__(message)
        self.message = message


class WarningList():

    def __init__(self, warninglist):
        self.warninglist = warninglist
        self.list = self.warninglist['list']
        self.description = self.warninglist['description']
        self.version = int(self.warninglist['version'])
        self.name = self.warninglist['name']
        if self.warninglist.get('type'):
            self.type = self.warninglist['type']
        if self.warninglist.get('matching_attributes'):
            self.matching_attributes = self.warninglist['matching_attributes']

    def to_dict(self):
        to_return = {'list': [str(e) for e in self.list], 'name': self.name,
                     'description': self.description, 'version': self.version}
        if hasattr(self, 'type'):
            to_return['type'] = self.type
        if hasattr(self, 'matching_attributes'):
            to_return['matching_attributes'] = self.matching_attributes
        return to_return

    def to_json(self):
        return json.dumps(self.to_dict(), cls=EncodeWarningList)

    def __contains__(self, value):
        if value in self.list:
            return True
        return False


class WarningLists(collections.Mapping):

    def __init__(self):
        self.root_dir_warninglists = os.path.join(os.path.abspath(os.path.dirname(sys.modules['pymispwarninglists'].__file__)),
                                                  'data', 'misp-warninglists', 'lists')
        self.warninglists = {}
        for warninglist_file in glob(os.path.join(self.root_dir_warninglists, '*', 'list.json')):
            with open(warninglist_file, 'r') as f:
                warninglist = json.load(f)
            self.warninglists[warninglist['name']] = WarningList(warninglist)

    def validate_with_schema(self):
        if not HAS_JSONSCHEMA:
            raise ImportError('jsonschema is required: pip install jsonschema')
        schema = os.path.join(os.path.abspath(os.path.dirname(sys.modules['pymispwarninglists'].__file__)),
                              'data', 'misp-warninglists', 'schema.json')
        with open(schema, 'r') as f:
            loaded_schema = json.load(f)
        for w in self.warninglists.values():
            jsonschema.validate(w.warninglist, loaded_schema)

    def __getitem__(self, name):
        return self.warninglists[name]

    def __iter__(self):
        return iter(self.warninglists)

    def search(self, value):
        matches = []
        for name, wl in self.warninglists.items():
            if value in wl:
               matches.append(wl)
        return matches

    def __len__(self):
        return len(self.warninglists)
