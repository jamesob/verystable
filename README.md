# `verystable`

*(Because it's not very stable.)*

This project contains a number of useful Python bindings for interaction with bitcoin.

Eventually it will contain a gallery of examples for doing useful things like
interacting with the P2P network and building interesting scripts.

> [!WARNING] 
> This project is not maintained with use of real (mainnet) funds in mind.
> The bulk of the code comes from a test framework that is intended for use with regtest
> only. You might lose money using this!

Notably, this project copies the [Bitcoin Core functional test
framework](https://github.com/bitcoin/bitcoin/tree/master/test/functional) in its
entirety for use, which contains a number of helpful utilities.

This gives us good utilities for interacting with the P2P layer
(`p2p.P2PInterface`) as well as handling process-level bitcoind invocation
(`test_node.TestNode`).

This module could help with a variety of tasks:

  - experimenting with script,
  - demonstrating proposals,
  - building a local relay which adapts the user's choice of
    protocol to bitcoin P2P messages,
  - monitoring via the P2P network,
  - programmatic management of bitcoind instances,
  - general utilities related to bitcoin,
  - and more.

## Installation

```sh
pip install verystable
```

or from source:

```sh
$ git clone https://github.com/jamesob/verystable.git
$ cd verystable
$ pip install -e .
```

Bitcoin Core test utilities (among other things) are then importable:
```python
$ python
>>> import verystable
>>> verystable.core.p2p.MAGIC_BYTES
{'mainnet': b'\xf9\xbe\xb4\xd9',
 'testnet3': b'\x0b\x11\t\x07',
 'regtest': b'\xfa\xbf\xb5\xda',
 'signet': b'\n\x03\xcf@'}
```

## Examples

Examples are contained in [examples/](examples/).

## Running tests

```
make docker-pull
make test
```

## Adding tests

Just add a function prefixed with `pytest` in any file and it will be collected by the
py.test runner.


## Pulling from upstream

To update the imported Bitcoin Core functional test framework code, 
- run `./pull-from-upstream.sh <bitcoin-core-repo-path>`
- examine/commit the diff
- bump the `pyproject.toml` version number if needed
