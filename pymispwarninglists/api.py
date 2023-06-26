#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import sys

from collections.abc import Mapping
from contextlib import suppress
from glob import glob
from ipaddress import ip_network, IPv6Address, IPv4Address, IPv4Network, _BaseNetwork, \
    AddressValueError, NetmaskValueError
from pathlib import Path
from typing import Union, Dict, Any, List, Optional, Tuple, Sequence
from urllib.parse import urlparse

from . import tools
from .exceptions import PyMISPWarningListsError

try:
    import jsonschema  # type: ignore
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


logger = logging.getLogger(__name__)


def json_default(obj: 'WarningList') -> Union[Dict, str]:
    if isinstance(obj, WarningList):
        return obj.to_dict()


class WarningList():

    expected_types = ['string', 'substring', 'hostname', 'cidr', 'regex']

    def __init__(self, warninglist: Dict[str, Any], slow_search: bool=False):
        self.warninglist = warninglist
        self.list = self.warninglist['list']
        self.set = set(self.list)
        self.description = self.warninglist['description']
        self.version = int(self.warninglist['version'])
        self.name = self.warninglist['name']
        if self.warninglist['type'] not in self.expected_types:
            raise PyMISPWarningListsError(f'Unexpected type ({self.warninglist["type"]}), please update the expected_type list')
        self.type = self.warninglist['type']
        if self.warninglist.get('matching_attributes'):
            self.matching_attributes = self.warninglist['matching_attributes']

        self.slow_search = slow_search

        if self.slow_search and self.type == 'cidr':
            self._ipv4_filter, self._ipv6_filter = compile_network_filters(self.list)

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
        return value in self.set

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
            with suppress(AddressValueError, NetmaskValueError):
                ipv4 = IPv4Address(value)
                return int(ipv4) in self._ipv4_filter
            with suppress(AddressValueError, NetmaskValueError):
                ipv6 = IPv6Address(value)
                return int(ipv6) in self._ipv6_filter
            # The value to search isn't an IP address, falling back to default
            return self._fast_search(value)
        return False


class WarningLists(Mapping):

    def __init__(self, slow_search: bool=False, lists: Optional[List]=None, from_xdg_home: bool=False, path_to_repo: Optional[Path]= None):
        """Load all the warning lists from the package.
        :slow_search: If true, uses the most appropriate search method. Can be slower. Default: exact match.
        :lists: A list of warning lists (typically fetched from a MISP instance)
        """
        if not lists:
            if from_xdg_home:
                path_to_repo = tools.get_xdg_home_dir()
                if not path_to_repo.exists():
                    tools.update_warninglists()

            if not path_to_repo or not path_to_repo.exists():
                path_to_repo = Path(sys.modules['pymispwarninglists'].__file__).parent / 'data' / 'misp-warninglists'  # type: ignore

            lists = []
            self.root_dir_warninglists = path_to_repo / 'lists'
            for warninglist_file in glob(str(self.root_dir_warninglists / '*' / 'list.json')):
                with open(warninglist_file, mode='r', encoding="utf-8") as f:
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


class NetworkFilter:
    def __init__(self, digit_position: int, digit2filter: Optional[Dict[int, Union[bool, "NetworkFilter"]]] = None):
        self.digit2filter: Dict[int, Union[bool, NetworkFilter]] = digit2filter or {0: False, 1: False}
        self.digit_position = digit_position

    def __contains__(self, ip: int) -> bool:
        child = self.digit2filter[self._get_digit(ip)]
        if isinstance(child, bool):
            return child

        return ip in child

    def append(self, net: _BaseNetwork) -> None:
        digit = self._get_digit(int(net.network_address))

        if net.max_prefixlen - net.prefixlen == self.digit_position:
            self.digit2filter[digit] = True
            return

        child = self.digit2filter[digit]

        if child is False:
            child = NetworkFilter(self.digit_position - 1)
            self.digit2filter[digit] = child

        if child is not True:
            child.append(net)

    def _get_digit(self, ip: int) -> int:
        return (ip >> self.digit_position) & 1

    def __repr__(self):
        return f"NetworkFilter(digit_position={self.digit_position}, digit2filter={self.digit2filter})"

    def __eq__(self, other):
        return isinstance(other, NetworkFilter) and self.digit_position == other.digit_position and self.digit2filter == other.digit2filter


def compile_network_filters(values: list) -> Tuple[NetworkFilter, NetworkFilter]:
    networks = convert_networks(values)

    ipv4_filter = NetworkFilter(31)
    ipv6_filter = NetworkFilter(127)

    for net in networks:
        root = ipv4_filter if isinstance(net, IPv4Network) else ipv6_filter
        root.append(net)

    return ipv4_filter, ipv6_filter


def convert_networks(values: list) -> Sequence[_BaseNetwork]:
    valid_ips = []
    invalid_ips = []

    for value in values:
        try:
            valid_ips.append(ip_network(value))
        except ValueError:
            invalid_ips.append(value)

    if invalid_ips:
        logger.warning(f'Invalid IPs found: {invalid_ips}')

    return valid_ips
