#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import unittest

from glob import glob
from ipaddress import IPv4Network

from pymispwarninglists import WarningLists, tools, WarningList
from pymispwarninglists.api import compile_network_filters, NetworkFilter


class TestPyMISPWarningLists(unittest.TestCase):

    def setUp(self):
        self.warninglists = WarningLists()

    def test_dump_warninglists(self):
        warninglists_from_files = {}
        for warninglist_file in glob(os.path.join(self.warninglists.root_dir_warninglists, '*', 'list.json')):
            with open(warninglist_file, mode='r', encoding="utf-8") as f:
                warninglist = json.load(f)
            warninglists_from_files[warninglist['name']] = warninglist
        for name, w in self.warninglists.items():
            out = w.to_dict()
            self.assertDictEqual(out, warninglists_from_files[w.name])

    def test_validate_schema_warninglists(self):
        self.warninglists.validate_with_schema()

    def test_json(self):
        for w in self.warninglists.values():
            w.to_json()

    def test_search(self):
        results = self.warninglists.search('8.8.8.8')
        self.assertEqual(results[0].name, 'List of known IPv4 public DNS resolvers')

    def test_slow_search(self):
        self.warninglists = WarningLists(True)
        results = self.warninglists.search('8.8.8.8')
        self.assertIn('List of known IPv4 public DNS resolvers', [r.name for r in results])
        results = self.warninglists.search('100.64.1.56')
        self.assertEqual(results[0].name, 'List of RFC 6598 CIDR blocks')
        results = self.warninglists.search('2001:DB8::34:1')
        self.assertEqual(results[0].name, 'List of RFC 3849 CIDR blocks')
        results = self.warninglists.search('1e100.net')
        self.assertTrue('List of known google domains' in [r.name for r in results])
        results = self.warninglists.search('blah.files.1drv.com')
        self.assertTrue('Top 10K most-used sites from Tranco' in [r.name for r in results])
        results = self.warninglists.search('arbitrary-domain-1e100.net')
        self.assertEqual(results, [])
        results = self.warninglists.search('phishing.co.uk')
        self.assertEqual(results, [])

    def test_fetch_xdg(self):
        tools.update_warninglists()
        self.assertTrue(tools.get_xdg_home_dir().exists())
        warninglists = WarningLists(from_xdg_home=True)
        self.assertEqual(len(warninglists), len(self.warninglists))


class TestCidrList(unittest.TestCase):

    cidr_list: WarningList

    @classmethod
    def setUpClass(cls) -> None:
        cls.cidr_list = WarningList(
            {
                "list": [
                    "1.1.1.1",
                    "51.8.152.0/21", "51.8.160.128/25",
                    "2a01:4180:4051::400",
                    "2a01:4180:c003:8::/61",
                ],
                "description": "Test CIDR list",
                "version": 0,
                "name": "Test CIDR list",
                "type": "cidr",
            },
            slow_search=True
        )

    def test_exact_match(self):
        assert "1.1.1.1" in self.cidr_list
        assert "2a01:4180:4051::400" in self.cidr_list

        assert "3.3.3.3" not in self.cidr_list
        assert "2a01:4180:4051::401" not in self.cidr_list

    def test_ipv4_bloc(self):
        # 51.8.152.0/21
        assert "51.8.152.0" in self.cidr_list
        assert "51.8.152.255" in self.cidr_list
        assert "51.8.153.0" in self.cidr_list
        assert "51.8.159.255" in self.cidr_list

        # outside
        assert "51.8.151.0" not in self.cidr_list
        assert "51.8.160.0" not in self.cidr_list

        # 51.8.160.128/25
        assert "51.8.160.128" in self.cidr_list
        assert "51.8.160.255" in self.cidr_list

    def test_ipv6_bloc(self):
        assert "2a01:4180:c003:8::" in self.cidr_list
        assert "2a01:4180:c003:8::1" in self.cidr_list
        assert "2a01:4180:c003:8::ffff" in self.cidr_list
        assert "2a01:4180:c003:9::1000" in self.cidr_list

        assert "2a01:4180:c003:7::ffff" not in self.cidr_list
        assert "2a01:4180:c003:10::" not in self.cidr_list

    def test_search_for_ipv4_bloc(self):
        assert "51.8.152.0/21" in self.cidr_list

        assert "51.8.152.0/22" not in self.cidr_list

    def test_search_for_ipv4_as_int(self):
        # 51.8.152.0 as integer is 864710656
        assert 856201216 in self.cidr_list


class TestNetworkCompilation(unittest.TestCase):
    def test_simple_case(self):
        ipv4_filter, ipv6_filter = compile_network_filters([IPv4Network("160.0.0.0/3"), IPv4Network("192.0.0.0/2")])

        assert ipv6_filter == NetworkFilter(127)
        assert ipv4_filter == NetworkFilter(
            digit_position=31,
            digit2filter={
                0: False,
                1: NetworkFilter(
                    digit_position=30,
                    digit2filter={
                        0: NetworkFilter(
                            digit_position=29,
                            digit2filter={
                                0: False,
                                1: True
                            }
                        ),
                        1: True
                    },
                ),
            },
        ), ipv4_filter

    def test_overwrite_with_bigger_network(self):
        ipv4_filter, ipv6_filter = compile_network_filters([IPv4Network("192.0.0.0/2"), IPv4Network("128.0.0.0/1")])

        assert ipv6_filter == NetworkFilter(127)
        assert ipv4_filter == NetworkFilter(
            digit_position=31,
            digit2filter={
                0: False,
                1: True,
            },
        ), ipv4_filter

    def test_dont_overwrite_with_smaller_network(self):
        ipv4_filter, ipv6_filter = compile_network_filters([IPv4Network("128.0.0.0/1"), IPv4Network("192.0.0.0/2")])

        assert ipv6_filter == NetworkFilter(127)
        assert ipv4_filter == NetworkFilter(
            digit_position=31,
            digit2filter={
                0: False,
                1: True,
            },
        ), ipv4_filter
