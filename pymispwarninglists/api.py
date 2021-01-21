#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import collections
from glob import glob
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse
from typing import Union, Dict, Any, List, Optional

try:
    import jsonschema  # type: ignore
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def json_default(obj: 'WarningList') -> Union[Dict, str]:
    if isinstance(obj, WarningList):
        return obj.to_dict()


class PyMISPWarningListsError(Exception):
    def __init__(self, message: str):
        super(PyMISPWarningListsError, self).__init__(message)
        self.message = message


class WarningList():

    expected_types = ['string', 'substring', 'hostname', 'cidr', 'regex']

    def __init__(self, warninglist: Dict[str, Any], slow_search: bool=False):
        self.warninglist = warninglist
        self.list = self.warninglist['list']
        self.description = self.warninglist['description']
        self.version = int(self.warninglist['version'])
        self.name = self.warninglist['name']
        if self.warninglist['type'] not in self.expected_types:
            raise PyMISPWarningListsError(f'Unexpected type ({self.warninglist["type"]}), please update the expected_type list')
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

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(type="{self.name}", version="{self.version}", description="{self.description}")'

    def __contains__(self, value: str) -> bool:
        if self.slow_search:
            return self._slow_search(value)
        return self._fast_search(value)

    def to_dict(self) -> Dict:
        to_return = {'list': [str(e) for e in self.list], 'name': self.name,
                     'description': self.description, 'version': self.version,
                     'type': self.type}
        if hasattr(self, 'matching_attributes'):
            to_return['matching_attributes'] = self.matching_attributes
        return to_return

    def to_json(self) -> str:
        return json.dumps(self, default=json_default)

    def _fast_search(self, value) -> bool:
        return value in self.list

    def _network_index(self) -> List:
        to_return = []
        for entry in self.list:
            try:
                # Try if the entry is a network bloc or an IP
                to_return.append(ip_network(entry))
            except ValueError:
                pass
        return to_return

    def _slow_search(self, value: str) -> bool:
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
            parsed_url = urlparse(value)
            if parsed_url.hostname:
                value = parsed_url.hostname
            return any(value == v or value.endswith("." + v.lstrip(".")) for v in self.list)
        elif self.type == 'cidr':
            try:
                value = ip_address(value)
            except ValueError:
                # The value to search isn't an IP address, falling back to default
                return self._fast_search(value)
            return any((value == obj or value in obj) for obj in self._network_objects)
        return False


class WarningLists(collections.Mapping):

    def __init__(self, slow_search: bool=False, lists: Optional[List]=None):
        """Load all the warning lists from the package.
        :slow_search: If true, uses the most appropriate search method. Can be slower. Default: exact match.
        :lists: A list of warning lists (typically fetched from a MISP instance)
        """
        if not lists:
            lists = []
            self.root_dir_warninglists = Path(sys.modules['pymispwarninglists'].__file__).parent / 'data' / 'misp-warninglists' / 'lists'
            for warninglist_file in glob(str(self.root_dir_warninglists / '*' / 'list.json')):
                with open(warninglist_file, 'r') as f:
                    lists.append(json.load(f))
        if not lists:
            raise PyMISPWarningListsError('Unable to load the lists. Do not forget to initialize the submodule (git submodule update --init).')
        self.warninglists = {}
        for warninglist in lists:
            self.warninglists[warninglist['name']] = WarningList(warninglist, slow_search)

    def validate_with_schema(self):
        if not HAS_JSONSCHEMA:
            raise ImportError('jsonschema is required: pip install jsonschema')
        schema = Path(sys.modules['pymispwarninglists'].__file__).parent / 'data' / 'misp-warninglists' / 'schema.json'
        with open(schema, 'r') as f:
            loaded_schema = json.load(f)
        for w in self.warninglists.values():
            jsonschema.validate(w.warninglist, loaded_schema)

    def __getitem__(self, name):
        return self.warninglists[name]

    def __iter__(self):
        return iter(self.warninglists)

    def search(self, value) -> List:
        matches = []
        for name, wl in self.warninglists.items():
            if value in wl:
                matches.append(wl)
        return matches

    def __len__(self):
        return len(self.warninglists)

    def get_loaded_lists(self):
        return self.warninglists
