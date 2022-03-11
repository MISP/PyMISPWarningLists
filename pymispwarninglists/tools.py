#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil

from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from .exceptions import PyMISPWarningListsError

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def get_xdg_home_dir() -> Path:
    if os.getenv('XDG_MISP_HOME'):
        xdg_home_dir = Path(os.environ['XDG_MISP_HOME'])
        if not xdg_home_dir.exists():
            xdg_home_dir.mkdir(parents=True)
        return xdg_home_dir / 'misp-warninglists'
    if os.name != 'posix':
        raise PyMISPWarningListsError('Cannot initialize XDG variable for OS {os.name}. Must be posix.')
    shared_data_dir = Path(os.environ['XDG_DATA_HOME']) if os.environ.get('XDG_DATA_HOME') else Path.home() / '.local' / 'share'
    xdg_home_dir = shared_data_dir / 'misp'
    if not xdg_home_dir.exists():
        xdg_home_dir.mkdir(parents=True)
    os.putenv('XDG_MISP_HOME', str(xdg_home_dir))
    return xdg_home_dir / 'misp-warninglists'


def update_warninglists():
    if not HAS_REQUESTS:
        raise PyMISPWarningListsError('Cannot update local warning lists, please install pymispwarninglists this way: pip install -E fetch_lists pymispwarninglists ')
    storage_dir = get_xdg_home_dir()
    if storage_dir.exists():
        shutil.rmtree(storage_dir)
    r = requests.get('https://github.com/MISP/misp-warninglists/archive/refs/heads/main.zip')
    r.raise_for_status()
    with ZipFile(BytesIO(r.content)) as zipfile:
        zipfile.extractall(storage_dir.parent)
    os.rename(storage_dir.parent / 'misp-warninglists-main', storage_dir)
