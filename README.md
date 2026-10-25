# PyMISPWarningLists

[![Build Status](https://travis-ci.org/MISP/PyMISPWarningLists.svg?branch=master)](https://travis-ci.org/MISP/PyMISPWarningLists)
[![codecov.io](https://codecov.io/github/MISP/PyMISPWarningLists/coverage.svg?branch=master)](https://codecov.io/github/MISP/PyMISPWarningLists?branch=master)

Pythonic way to work with the warning lists defined there: https://github.com/MISP/misp-warninglists

# Installation

`pip install pymispwarninglists`

# Usage

Warning lists are represented as immutable Python dictionaries.

# Updating bundled warning lists

The bundled data is pinned to a commit of the `MISP/misp-warninglists` Git
submodule. Dependabot checks for updates daily and opens a pull request when
upstream changes, keeping at most one submodule update PR open. The existing
Python test and type-check workflow runs on these PRs. Review and merge an
update PR to refresh the data bundled in the next package release.

To update the data manually from the repository root:

```bash
git submodule update --init --recursive
git -C pymispwarninglists/data/misp-warninglists fetch origin main
git -C pymispwarninglists/data/misp-warninglists checkout --detach origin/main
poetry run pytest --cov=pymispwarninglists tests/tests.py
poetry run mypy .
git add pymispwarninglists/data/misp-warninglists
```

Commit the updated submodule pointer and open a pull request. Package releases
continue to use the reviewed, pinned commit; the download helper
`tools.update_warninglists()` fetches the latest upstream data separately.

