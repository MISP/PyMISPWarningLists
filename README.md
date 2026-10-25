# PyMISPWarningLists

[![Tests](https://github.com/MISP/PyMISPWarningLists/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/MISP/PyMISPWarningLists/actions/workflows/pytest.yml)
[![codecov.io](https://codecov.io/github/MISP/PyMISPWarningLists/coverage.svg?branch=main)](https://codecov.io/github/MISP/PyMISPWarningLists?branch=main)

Python API for the [MISP warning lists](https://github.com/MISP/misp-warninglists).
Search domains, IP addresses, URLs, and other values against lists of common
services and known infrastructure to help identify potential false positives
in threat intelligence. Bundled lists are included with the package, so the
default lookup works offline and does not require a MISP instance.

## Installation

Requires **Python 3.10 or newer**.

```bash
python -m pip install pymispwarninglists
```

## Quick start

```python
from pymispwarninglists import WarningLists

warninglists = WarningLists()
matches = warninglists.search("8.8.8.8")

for match in matches:
    print(match.name, match.type, match.description)
```

`search()` returns a list of matching `WarningList` objects, or an empty list
when nothing matches. `WarningLists` is a mapping keyed by list name; individual
lists expose their entries and metadata, support membership checks, and can be
serialized:

```python
dns_resolvers = warninglists["List of known IPv4 public DNS resolvers"]

print("8.8.8.8" in dns_resolvers)  # True
print(dns_resolvers.version)
print(dns_resolvers.to_dict())
print(dns_resolvers.to_json())

for name, warninglist in warninglists.items():
    print(name, len(warninglist.list))
```

See [example_domaincheck.py](example_domaincheck.py) for a domain lookup example.

## Search modes

The default, `WarningLists()`, checks for exact membership in each list. Use
`slow_search=True` to enable matching based on the list type:

```python
from pymispwarninglists import WarningLists

warninglists = WarningLists(slow_search=True)

for match in warninglists.search("100.64.1.56"):
    print(match.name)  # Includes "List of RFC 6598 CIDR blocks"
```

| List type | Default search | With `slow_search=True` |
| --- | --- | --- |
| `string` | Exact match | Exact match |
| `substring` | Exact match | A list entry occurs anywhere in the value |
| `hostname` | Exact match | Matches a hostname or its subdomains; also extracts the hostname from a URL |
| `cidr` | Exact match | Checks IPv4 and IPv6 addresses against listed networks; non-address values fall back to exact matching |
| `regex` | Exact match | Not implemented; returns no match |

Choose the mode when creating `WarningLists`; it applies to searches across
the collection and membership checks on its individual lists.

## Loading and refreshing lists

By default, `WarningLists()` loads the snapshot bundled with the installed
package. Upgrade the package to get its latest bundled snapshot:

```bash
python -m pip install --upgrade pymispwarninglists
```

To download the current upstream lists independently of package releases,
install the optional download dependency:

```bash
python -m pip install "pymispwarninglists[fetch_lists]"
```

```python
from pymispwarninglists import WarningLists, tools

tools.update_warninglists()
warninglists = WarningLists(from_xdg_home=True)
```

The download helper requires network access and replaces the cached lists.
`from_xdg_home=True` uses that cache and downloads it if it does not exist;
it does not automatically refresh an existing cache. Create a new `WarningLists`
instance after updating to load the refreshed data.

On POSIX systems, the default cache location is
`$XDG_DATA_HOME/misp/misp-warninglists`, or
`~/.local/share/misp/misp-warninglists` when `XDG_DATA_HOME` is unset. Set
`XDG_MISP_HOME` to override the parent directory of `misp-warninglists`;
this explicit setting is required for the cache helper on non-POSIX systems.

You can also load an existing local checkout:

```python
from pathlib import Path
from pymispwarninglists import WarningLists

warninglists = WarningLists(path_to_repo=Path("/path/to/misp-warninglists"))
```

The path should point to the repository containing `lists/*/list.json`.
Alternatively, pass a non-empty list of warning-list dictionaries using
`WarningLists(lists=[...])`, for example with data fetched from a MISP instance.

## Development

Clone with submodules to include the warning-list data, then install dependencies
with [Poetry](https://python-poetry.org/docs/#installation):

```bash
git clone --recurse-submodules https://github.com/MISP/PyMISPWarningLists.git
cd PyMISPWarningLists
poetry install -E fetch_lists
poetry run pytest --cov=pymispwarninglists tests/tests.py
poetry run mypy .
```

The tests include a download check that requires network access. If an existing
checkout raises `Unable to load the lists`, initialize its submodule:

```bash
git submodule update --init --recursive
```

Schema validation is available through `warninglists.validate_with_schema()`
and requires `jsonschema`, which is included in the development dependencies.
For a regular installation, add it with `python -m pip install jsonschema`.

## Updating bundled warning lists

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

## License

[BSD 3-Clause](LICENSE).

