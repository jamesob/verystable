#!/bin/bash

# This can be run periodically to pull in upstream changes from Bitcoin Core's
# functional test framework.

set -xe

CORE_REPO_DIR=${1:-$HOME/src/bitcoin}
TARGET=./verystable/core

if [ ! -d "${CORE_REPO_DIR}" ]; then
    echo "Bitcoin Core not found in ${CORE_REPO_DIR}"
    exit 1
fi

rm -rf ${TARGET}
cp -r ${CORE_REPO_DIR}/test/functional/test_framework ${TARGET}
rm -rf ${TARGET}/__pycache__

for f in $(ls ./core-overlay/); do
    cp ./core-overlay/${f} ${TARGET}/${f}
done

find $(pwd)/${TARGET} -type f -print0 | \
    xargs -0 sed -i 's/^from test_framework\./from ./g'
find $(pwd)/${TARGET} -type f -print0 | \
    xargs -0 sed -i 's/^from test_framework/from ./g'
