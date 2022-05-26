#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Koen Van Impe

Demo script for domain check against warninglists

'''

from pymispwarninglists import WarningLists


def init():
    '''
        Template to get the module started.
        If set slow_search=True, uses the most appropriate search method. Can be slower.
    '''
    return WarningLists(slow_search=False)


if __name__ == '__main__':
    warninglists = init()

    # Fetch this list of domains from MISP via PyMISP search
    # For demo purpose we put it in a Python list
    domain_list = ['google.com', 'circl.lu']

    for domain in domain_list:
        r = warninglists.search(domain)
        if r:
            # Now update the attribute for the domain
            # Attribute ID can be included when querying the domains via PyMISP
            # If a hit is found, set the tag for the attribute
            print("Hit found for %s in warninglists" % (domain))
            for hit in r:
                print(" %s %s %s %s" % (hit.type, hit.name, hit.version, hit.description))
