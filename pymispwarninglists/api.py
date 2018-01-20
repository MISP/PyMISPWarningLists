#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from json import JSONEncoder
import os
import sys
import collections
from glob import glob
from ipaddress import ip_address, ip_network
import re


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

    expected_types = ['string', 'substring', 'hostname', 'cidr', 'regex']

    def __init__(self, warninglist, slow_search=False):
        self.warninglist = warninglist
        self.list = self.warninglist['list']
        self.description = self.warninglist['description']
        self.version = int(self.warninglist['version'])
        self.name = self.warninglist['name']
        if self.warninglist['type'] not in self.expected_types:
            raise Exception('Unexpected type, please update the expected_type list')
        self.type = self.warninglist['type']
        if self.warninglist.get('matching_attributes'):
            self.matching_attributes = self.warninglist['matching_attributes']

        self.slow_search = slow_search
        self._network_objects = []

        if self.slow_search and self.type == 'cidr':
            self._network_objects = self._network_index()
        # If network objects is empty, reverting to default anyway
        if not self._network_objects:
            self.slow_search = False

    def __contains__(self, value):
        if self.slow_search:
            return self._slow_search(value)
        return self._fast_search(value)

    def to_dict(self):
        to_return = {'list': [str(e) for e in self.list], 'name': self.name,
                     'description': self.description, 'version': self.version,
                     'type': self.type}
        if hasattr(self, 'matching_attributes'):
            to_return['matching_attributes'] = self.matching_attributes
        return to_return

    def to_json(self):
        return json.dumps(self, cls=EncodeWarningList)

    def _fast_search(self, value):
        return value in self.list

    def _network_index(self):
        to_return = []
        for entry in self.list:
            try:
                # Try if the entry is a network bloc or an IP
                to_return.append(ip_network(entry))
            except ValueError:
                pass
        return to_return

    # Get a string containing a potential list of valid modifiers - "|" the valid ones
    def setRegexFlags(modifiers):
        set_flags = False
        for modifier in modifiers:
            add_flag = False
            if modifier in ['i', 'm', 's', 'x']:
                add_flag = getattr(re, modifier.upper())
            if add_flag != False:
                if set_flags != False:
                    set_flags = set_flags | add_flag
                else:
                    set_flags = add_flag
        return set_flags

    def _slow_search(self, value):
        if self.type == 'string':
            # Exact match only, using fast search
            return self._fast_search(value)
        elif self.type == 'substring':
            # Expected to match on a part of the value
            # i.e.: value = 'blah.de' self.list == ['.fr', '.de']
            return any(v in value for v in self.list)
        elif self.type == 'hostname':
            # Expected to match on hostnames in URLs (i.e. the search query is a URL)
            # So we do a reverse search if any of the entries in the list are present in the URL
            # i.e.: value = 'http://foo.blah.de/meh' self.list == ['blah.de', 'blah.fr']
            return any(v in value for v in self.list)
        elif self.type == 'cidr':
            try:
                value = ip_address(value)
            except ValueError:
                # The value to search isn't an IP address, falling back to default
                return self._fast_search(value)
            return any((value == obj or value in obj) for obj in self._network_objects)
        elif self.type == 'regex':
            for regex in mylist:
                # PHP PCRE can have several delimiters such as /, #, + etc. Find out which it is
                delimiter = regex[0]
                # Find all of the potential delimiter characters, we only care about the first and last
                delimiters = [m.start() for m in re.finditer(regex[0], regex)]
                # If we don't have two delimiters the regex is incorrect, hop over it
                if len(delimiters) < 2:
                    continue
                # If we have characters after the delimiter, extract them, they can be modifiers
                modifiers = ""
                if delimiters[-1] < len(regex):
                    modifiers = regex[delimiters[-1]+1:]
                # The actual regex is between the first and last delimiters
                regex = regex[1:(delimiters[-1])]
                flags = setRegexFlags(modifiers)
                # Try to run the regex with modifiers or without depending on the above
                try:
                    if flags:
                        if re.search(regex, value, flags):
                            return True
                    else:
                        if re.search(regex, value):
                            return False
                except Exception:
                    continue
            return False


class WarningLists(collections.Mapping):

    def __init__(self, slow_search=False):
        """Load all the warning lists from the package.
        :slow_search: If true, uses the most appropriate search method. Can be slower. Default: exact match.
        """
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
