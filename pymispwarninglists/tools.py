#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import tempfile

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
    r = requests.get('https://github.com/MISP/misp-warninglists/archive/refs/heads/main.zip')
    r.raise_for_status()
    # Extract next to the final destination (same filesystem, so the swap below is a rename)
    # and only replace the existing warning lists once the new ones are fully extracted.
    tmp_dir = Path(tempfile.mkdtemp(prefix='misp-warninglists.', dir=storage_dir.parent))
    try:
        with ZipFile(BytesIO(r.content)) as zipfile:
            zipfile.extractall(tmp_dir)
        new_dir = tmp_dir / 'misp-warninglists-main'
        if not new_dir.is_dir():
            raise PyMISPWarningListsError('The downloaded archive does not contain a misp-warninglists-main directory.')
        old_dir = tmp_dir / 'misp-warninglists-old'
        if storage_dir.exists():
            os.rename(storage_dir, old_dir)
        try:
            os.rename(new_dir, storage_dir)
        except Exception:
            if old_dir.exists():
                os.rename(old_dir, storage_dir)
            raise
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
