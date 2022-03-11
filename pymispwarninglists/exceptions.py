#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class PyMISPWarningListsError(Exception):
    def __init__(self, message: str):
        super(PyMISPWarningListsError, self).__init__(message)
        self.message = message
