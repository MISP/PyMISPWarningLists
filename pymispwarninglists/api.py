#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from json import JSONEncoder
import os
import sys
import collections
from glob import glob
from ipaddress import ip_address, ip_network


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

    def __init__(self, warninglist, slow_search=False):
        self.warninglist = warninglist
        self.list = self.warninglist['list']
        self.description = self.warninglist['description']
        self.version = int(self.warninglist['version'])
        self.name = self.warninglist['name']
        if self.warninglist.get('type'):
            self.type = self.warninglist['type']
        if self.warninglist.get('matching_attributes'):
            self.matching_attributes = self.warninglist['matching_attributes']

        self.slow_search = slow_search
        self._network_objects = []

        if self.slow_search:
            self._network_objects = self._slow_index()
        # If network objects is empty, reverting to default anyway
        if not self._network_objects:
            self.slow_search = False

    def __contains__(self, value):
        if self.slow_search:
            return self._slow_search(value)
        return self._fast_search(value)

    def to_dict(self):
        to_return = {'list': [str(e) for e in self.list], 'name': self.name,
                     'description': self.description, 'version': self.version}
        if hasattr(self, 'type'):
            to_return['type'] = self.type
        if hasattr(self, 'matching_attributes'):
            to_return['matching_attributes'] = self.matching_attributes
        return to_return

    def to_json(self):
        return json.dumps(self, cls=EncodeWarningList)

    def _fast_search(self, value):
        return value in self.list

    def _slow_index(self):
        to_return = []
        for entry in self.list:
            try:
                # Try if the entry is a network bloc or an IP
                to_return.append(ip_network(entry))
            except ValueError:
                pass
        return to_return

    def _slow_search(self, value):
        try:
            value = ip_address(value)
        except ValueError:
            # The value to search isn't an IP address, falling back to default
            return self._fast_search(value)
        for obj in self._network_objects:
            if value == obj or value in obj:
                return True
        # If nothing has been found yet, fallback to default
        return self._fast_search(value)


class WarningLists(collections.Mapping):

    def __init__(self, slow_search=False):
        self.root_dir_warninglists = os.path.join(os.path.abspath(os.path.dirname(sys.modules['pymispwarninglists'].__file__)),
                                                  'data', 'misp-warninglists', 'lists')
        self.warninglists = {}
        for warninglist_file in glob(os.path.join(self.root_dir_warninglists, '*', 'list.json')):
            with open(warninglist_file, 'r') as f:
                warninglist = json.load(f)
            self.warninglists[warninglist['name']] = WarningList(warninglist, slow_search)

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
