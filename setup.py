#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup  # type: ignore


setup(
    name='pymispwarninglists',
    version='2.0-dev',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/MISP/PyMISPWarningLists',
    description='Python API for the MISP warning lists.',
    packages=['pymispwarninglists'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    tests_requires=['nose'],
    test_suite='nose.collector',
    package_data={'pymispwarninglists': ['data/misp-warninglists/schema.json',
                                         'data/misp-warninglists/lists/*/*.json']}
)
