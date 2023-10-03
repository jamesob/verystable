#!/bin/bash

set -ex

python -m build && twine check dist/*
twine upload dist/*
